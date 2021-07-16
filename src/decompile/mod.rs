#[macro_use] extern crate log;

use std::env;
use std::fs::{create_dir_all, File, remove_dir};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

use clap_conf::Getter;
use hex_literal::hex;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use log::Level::Debug;
use md5::{Digest, Md5};
use md5::digest::DynDigest;
use subprocess::{Popen, PopenConfig, Redirection};

use crate::{CommandArgConfig, exec_cmd, ExecError, FF_OUT, get_loading_style, process_cfg_str};
use crate::actions::{Action, ActionProgressBarManager, ActionResult};
use crate::lib::zip_extract::{extract_progress, ZipExtractResult};
use crate::multi_progress_manager::ProgressBarManager;
use crate::retroguard::{apply_retroguard, RETRO_GUARD_CLIENT_OUT, RETRO_GUARD_SERVER_OUT, write_retroguard_configs_once, writer_loading_size};
use crate::retroguard::mapping::write_srg_from_csv;

pub (crate) const MINECRAFT_JAR: &str = "%jars%/minecraft.jar";
pub (crate) const MINECRAFT_NATIVES: &str = "%jars%/natives";
pub (crate) const MINECRAFT_SERVER: &str = "%jars%/minecraft_server.jar";

pub (crate) const EXCEPTOR_JAR: &str = "%bin%/exceptor.jar";
pub (crate) const FF_JAR: &str = "%bin%/fernflower.jar";

const EXCEPTOR_CMD: &str = "%java% -jar %exceptor_jar% {input} {output} {conf} {log}";
const FF_CMD: &str = "%java% -jar %ff_jar% {conf} {jar_in} {jar_out}";

const PATCH_CMD_UNIX: &str = "patch --binary -p1 -u -i ../../{patch_file} -d {src_dir}";
const PATCH_CMD_WIN: &str = r"%bin%\patch.exe --binary -p1 -u -i ..\..\{patch_file} -d {src_dir}";

const MD5_CLIENT: &str = "ce80072464433cd5b05d505aa8ff29d1";
const MD5_SERVER: &str = "0563ccb08d4dc84634d561b7f4bea596";

const SRC_CLIENT: &str = "src/client";
const SRC_SERVER: &str = "src/server";

const FF_CONF: &str = "-rbr=0 -hes=0 -hdc=0 -dgs=1 -nns=0 -rer=0 -fdi=0 -asc=1";

const FF_OUT_CLIENT: &str = "%ff-out%/client";
const FF_OUT_SERVER: &str = "%ff-out%/server";

const FF_PATCH_CLIENT: &str = "patches/minecraft_ff.patch";
const FF_PATCH_SERVER: &str = "patches/minecraft_server_ff.patch";

const TEMP_PATCH: &str = "%temp%/temp.patch";

const EXCEPTOR_OUT_CLIENT: &str = "%temp%/minecraft_exc.jar";
const EXCEPTOR_OUT_SERVER: &str = "%temp%/minecraft_server_exc.jar";

const EXCEPTOR_CFG_CLIENT: &str = "%resources%/client.exc";
const EXCEPTOR_CFG_SERVER: &str = "%resources%/server.exc";

const EXCEPTOR_LOG_CLIENT: &str = "%logs%/client_exc.log";
const EXCEPTOR_LOG_SERVER: &str = "%logs%/server_exc.log";

pub type DecompileResult = Result<(), DecompileError>;
pub type ExceptorResult = Result<(), ExceptorError>;
pub type FernFlowerResult = Result<(), FernFlowerError>;

#[derive(Debug)]
pub enum DecompileError {
    ExtractError,
    SrcDirInvalid,
    SrcDirNotEmpty,
    SRGWriteError,
    ExceptorError,
    RetroGuardError,
    JarFileOpenError,
}

#[derive(Debug)]
pub enum ExceptorError {
    ExceptorRuntimeError,
}

#[derive(Debug)]
pub enum FernFlowerError {
    FernFlowerDecompileRuntimeError,
    PatchError,
}

struct DecompileAction {
    total_progress: ProgressBar,
    retro_guard_progress: ProgressBar,
    decompile_client_progress: ProgressBar,
    decompile_server_progress: ProgressBar,
}

impl Action for DecompileAction {
    fn do_action(&mut self, config: &CommandArgConfig) -> ActionResult {
        self.total_progress.set_prefix("Total");
        let rg_progress_manager: ActionProgressBarManager =
            ActionProgressBarManager::new(&self, Some(&self.total_progress));
        write_retroguard_configs_once(&config, rg_progress_manager);

        self.decompile_server_progress.set_prefix("Decompile Client");
        let cd_progress_manager: ActionProgressBarManager
            = ActionProgressBarManager::new(self, Some(&self.decompile_client_progress));
        decompile(true, &config, cd_progress_manager)?;

        self.decompile_server_progress.set_prefix("Decompile Server");
        let cd_progress_manager: ActionProgressBarManager
            = ActionProgressBarManager::new(self, Some(&self.decompile_server_progress));
        decompile(false, &config, cd_progress_manager)?;

        self.total_progress.finish_print("✓ Finished Decompiling");

        Ok(())
    }

    fn create_multi_bars(&mut self, config: &CommandArgConfig, multi_bar: &MultiProgress) {
        let retro_guard_total: u64 = writer_loading_size() as u64;
        let decompile_total: u64 = 0;
        let total: u64 = retro_guard_total + decompile_total;

        let style: ProgressStyle = get_loading_style();

        self.total_progress = multi_bar.add(ProgressBar::new(total));
        self.total_progress.set_style(style.clone());

        self.retro_guard_progress = multi_bar.add(ProgressBar::new(retro_guard_total));
        self.retro_guard_progress.set_style(style.clone());

        self.decompile_client_progress = multi_bar.add(ProgressBar::new(decompile_total));
        self.decompile_client_progress.set_style(style.clone());
    }

    fn get_total_progress(&self) -> &ProgressBar {
        &self.total_progress
    }
}

fn decompile(client: bool, config: &CommandArgConfig, mut progress_bar: ActionProgressBarManager) -> DecompileResult {
    progress_bar.message("Checking source dirs");

    let override_src: bool = config.matches().is_present("src override");
    let src: String = if client {
        config.grab().arg("src client output").conf("decompile.client-src").def(SRC_CLIENT)
    } else {
        config.grab().arg("src server output").conf("decompile.server-src").def(SRC_SERVER)
    };

    let side_str: &str = if client { "Client" } else { "Server" };

    let src_path: &Path = Path::new(src.as_str());

    if src_path.exists() && !src_path.is_dir() {
        error!("{} path given isn't a directory! {}", side_str, src);
        Err(DecompileError::SrcDirInvalid)
    }

    if !src_path.exists() || src_path.read_dir()?.next().is_none() || override_src {
        if override_src {
            remove_dir(src_path)?;
        }

        create_dir_all(src_path)?;
    } else {
        error!("{} directory isn't empty and the src override flag was not set! {}", side_str, src);
        Err(DecompileError::SrcDirNotEmpty)
    }

    progress_bar.message("Checking Minecraft jars");
    progress_bar.inc_multi_bar();

    match check_jars(client, &config) {
        Ok(()) => { },
        Err(e) => {
            error!("{} jar missing or failed to open! {}", side_str, e.to_string());
            Err(DecompileError::JarFileOpenError)
        }
    };

    progress_bar.message("Writing SRG mappings");
    progress_bar.inc_multi_bar();

    match write_srg_from_csv(client, &config) {
        Ok(()) => { },
        Err(e) => {
            error!("Failed to write SRG mapping files! {}", e.to_string());
            Err(DecompileError::SRGWriteError)
        }
    }

    progress_bar.message("Applying Mappings (De-Obfuscate)");
    progress_bar.inc_multi_bar();

    match apply_retroguard(client, &config, &progress_bar) {
        Ok(()) => { },
        Err(e) => {
            error!("Failed to apply mappings with RetroGuard! {}", e.to_string());
            Err(DecompileError::RetroGuardError)
        }
    }

    progress_bar.message("Applying Exceptor");
    progress_bar.inc_multi_bar();

    match apply_exceptor(client, &config, &progress_bar) {
        Ok(()) => { },
        Err(e) => {
            error!("Failed to apply Exceptor! {}", e.to_string());
            Err(DecompileError::ExceptorError)
        }
    }

    progress_bar.message("Decompiling..");
    progress_bar.inc_multi_bar();

    match fernflower_decompile(client, &config, &progress_bar) {
        Ok(()) => { },
        Err(e) => {
            error!("Failed to decompile! {}", e.to_string());
            Err(DecompileError::ExceptorError)
        }
    }

    progress_bar.message("Extracting sources");
    progress_bar.inc_multi_bar();

    match extract_decompiled_src(client, &config, &progress_bar) {
        Ok(()) => { },
        Err(e) => {
            error!("Failed to extract FernFlower sources! {}", e.to_string());
            Err(DecompileError::ExceptorError)
        }
    }

    Ok(())
}

fn check_jars(client: bool, config: &CommandArgConfig) -> std::io::Result<()> {
    let path: &str = if client { MINECRAFT_JAR } else { MINECRAFT_SERVER };
    let jar_path: String = process_cfg_str(path, &config, None);

    let md5: &str = if client { MD5_CLIENT } else { MD5_SERVER };

    // Will return an Error if missing
    let mut jar_file: File = File::open(jar_path)?;

    let mut bytes: Vec<u8> = Vec::new();
    jar_file.read_to_end(&mut bytes)?;

    let mut hasher: Md5 = Md5::new();
    hasher.update(bytes);

    let result = hasher.finalize();

    if result[..] != hex!(md5) {
        let jar_env_str: &str = if client { "client" } else { "server" };

        warn!("Modified JAR detected, unpredictable results - {}", jar_env_str);
        debug!("{} jar md5: {}", jar_env_str, md5);
    }

    Ok(())
}

fn apply_exceptor(client: bool, config: &CommandArgConfig, mut progress_bar_mgr: &ActionProgressBarManager) -> ExceptorResult {
    let ex_input: &str = if client { RETRO_GUARD_CLIENT_OUT } else { RETRO_GUARD_SERVER_OUT };

    let ex_output: &str = if client { EXCEPTOR_OUT_CLIENT } else { EXCEPTOR_OUT_SERVER };
    let ex_conf: &str = if client { EXCEPTOR_CFG_CLIENT } else { EXCEPTOR_CFG_SERVER };
    let ex_log: &str = if client { EXCEPTOR_LOG_CLIENT } else { EXCEPTOR_LOG_SERVER };

    let proc_input: String = process_cfg_str(ex_input, &config, None);
    let proc_output: String = process_cfg_str(ex_output, &config, None);
    let proc_conf: String = process_cfg_str(ex_conf, &config, None);
    let proc_log: String = process_cfg_str(ex_log, &config, None);

    let cmd_proc: String = process_cfg_str(EXCEPTOR_CMD, &config, None);
    let cmd_str: &str = format!(cmd_proc, input = proc_input, output = proc_output, conf = proc_conf, log = proc_log).as_str();

    match exec_cmd(cmd_str, Some(&mut progress_bar_mgr)) {
        Ok(()) => { },
        Err(e) => {
            match e {
                ExecError::ExitCodeError { exit_code, exit_code_str } => {
                    error!("Exceptor failed! With return code: {} : {}\nAdditional details can be found in the logs", exit_code, exit_code_str);
                }
            }

            Err(ExceptorError::ExceptorRuntimeError)
        }
    }

    Ok(())
}

fn fernflower_decompile(client: bool, config: &CommandArgConfig, mut progress_bar_mgr: &ActionProgressBarManager) -> FernFlowerResult {
    let input: &str = if client { EXCEPTOR_OUT_CLIENT } else { EXCEPTOR_OUT_SERVER };

    let input_proc: String = process_cfg_str(input, &config, None);
    let output_proc: String = process_cfg_str(FF_OUT, &config, None);

    let cmd_proc: String = process_cfg_str(FF_CMD, &config, None);
    let cmd_str: &str = format!(cmd_proc, conf = FF_CONF, jar_in = input_proc, jar_out = output_proc, log = proc_log).as_str();

    match exec_cmd(cmd_str, Some(&mut progress_bar_mgr)) {
        Ok(()) => { },
        Err(e) => {
            match e {
                ExecError::ExitCodeError { exit_code, exit_code_str } => {
                    error!("FernFlower decompile failed! With return code: {} : {}\nAdditional details can be found in the logs", exit_code, exit_code_str);
                }
            }

            Err(FernFlowerError::FernFlowerDecompileRuntimeError)
        }
    }

    Ok(())
}

fn extract_decompiled_src(client: bool, config: &CommandArgConfig, mut progress_bar_mgr: &ActionProgressBarManager) -> ZipExtractResult {
    let out: &str = if client { FF_OUT_CLIENT } else { FF_OUT_SERVER };
    let jar: &str = if client { EXCEPTOR_OUT_CLIENT } else { EXCEPTOR_OUT_SERVER };

    let out_proc: String = process_cfg_str(out, &config, None);
    let jar_proc: String = process_cfg_str(jar, &config, None);

    let out_dir: PathBuf = PathBuf::from(out_proc);
    let jar_file: File = File::open(jar_proc)?;

    extract_progress(Cursor::new(jar_file.bytes()), &out_dir, false, Some(progress_bar_mgr))
}

fn apply_fernflower_patches(client: bool, config: &CommandArgConfig, mut progress_bar_mgr: &ActionProgressBarManager) -> FernFlowerResult {
    let patch_path: &str = if client { FF_PATCH_CLIENT } else { FF_PATCH_SERVER };
    let patch_bytes: &[u8] = Resources::get(patch_path).unwrap()?;
    let patch_string: &str = std::str::from_utf8(patch_bytes.as_ref())?;
    let patch_fixed: String = patch_string.replace("\\", std::path::MAIN_SEPARATOR.into())
        .replace("/", std::path::MAIN_SEPARATOR.into());

    let temp_patch_path: String = process_cfg_str(TEMP_PATCH, &config, None);
    let mut temp_patch_file: File = File::create(temp_patch_path)?;
    temp_patch_file.write_all(patch_fixed.as_bytes())?;

    let patch: Patch<str> = Patch::from_str(patch_fixed.as_str())?;

    let os: &str = env::consts::OS;
    let cmd: &str = match os {
        "windows" => PATCH_CMD_WIN,
        _ => PATCH_CMD_UNIX,
    };

    let cmd_proc: String = process_cfg_str(cmd, &config, None);
    let cmd_str: &str = format!(cmd_proc, patch_file = temp_patch_path, src_dir = ).as_str();

    match exec_cmd(cmd_str, Some(&mut progress_bar_mgr)) {
        Ok(()) => { },
        Err(e) => {
            match e {
                ExecError::ExitCodeError { exit_code, exit_code_str } => {
                    error!("FernFlower patches failed! With return code: {} : {}\nAdditional details can be found in the logs", exit_code, exit_code_str);
                }
            }

            Err(FernFlowerError::PatchError)
        },
    }

    Ok(())
}