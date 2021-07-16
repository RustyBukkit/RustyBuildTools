#[macro_use]
extern crate lazy_static;

use std::borrow::Borrow;
use std::collections::HashMap;
use std::convert::TryInto;
use std::fs::File;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use crate::{CommandArgConfig, exec_cmd, ExecError, process_cfg_str};
use crate::decompile::{ActionProgressBarManager, MINECRAFT_JAR, MINECRAFT_SERVER};
use crate::multi_progress_manager::ProgressBarManager;

pub mod mapping;

pub (crate) const RETRO_GUARD_JAR: &str = "%bin%/retroguard.jar";

const RETRO_GUARD_CMD: &str = "%java% -cp %retro_guard_jar%/{class_path} RetroGuard -searge {conf_file}";

const RETRO_GUARD_CFG: &str = "%temp%/retroguard.cfg";
const RETRO_GUARD_CLIENT_CFG: &str = "%temp%/client_rg.cfg";
const RETRO_GUARD_SERVER_CFG: &str = "%temp%/server_rg.cfg";

pub (crate) const RETRO_GUARD_CLIENT_OUT: &str = "%temp%/minecraft_rg.jar";
pub (crate) const RETRO_GUARD_SERVER_OUT: &str = "%temp%/minecraft_server_rg.jar";

const RETRO_GUARD_CLIENT_RECOMP: &str = "%temp%/client_recomp.jar";
const RETRO_GUARD_SERVER_RECOMP: &str = "%temp%/server_recomp.jar";

const RETRO_GUARD_CLIENT_REOBF: &str = "%temp%/client_reobf.jar";
const RETRO_GUARD_SERVER_REOBF: &str = "%temp%/server_reobf.jar";

const RETRO_GUARD_CLIENT_OBF: &str = "%temp%/client_obf.srg";
const RETRO_GUARD_SERVER_OBF: &str = "%temp%/server_obf.srg";

const RETRO_GUARD_CLIENT_LOG: &str = "%logs%/client_rg.log";
const RETRO_GUARD_SERVER_LOG: &str = "%logs%/server_rg.log";

const RETRO_GUARD_CLIENT_DEOBF_LOG: &str = "%logs%/client_deobf.log";
const RETRO_GUARD_SERVER_DEOBF_LOG: &str = "%logs%/server_deobf.log";

const RETRO_GUARD_CLIENT_REOBF_LOG: &str = "%logs%/client_reobf.log";
const RETRO_GUARD_SERVER_REOBF_LOG: &str = "%logs%/server_reobf.log";

const SRG_CLIENT: &str = "%temp%/client_rg.srg";
const SRG_SERVER: &str = "%temp%/server_rg.srg";

const RETRO_GUARD_CLIENT_CLASS_PATH: &str = "lib/,lib/*,%jars%/bin/minecraft.jar,%jars%/bin/jinput.jar,%jars%/bin/lwjgl.jar,%jars%/bin/lwjgl_util.jar";
const RETRO_GUARD_SERVER_CLASS_PATH: &str = "lib/,lib/*,%jars%/minecraft_server.jar";

const RETRO_GUARD_DEFAULT_CFG: Vec<&str> = vec![
    ".option Application\n",
    ".option Applet\n",
    ".option Repackage\n",
    ".option Annotations\n",
    ".attribute LineNumberTable\n",
    ".attribute EnclosingMethod\n",
    ".attribute Deprecated\n",
];

const IGNORE_PACKAGES: Vec<&str> = vec![
    "paulscode",
    "com/jcraft",
    "ibxm",
    "de/matthiasmann/twl",
    "org/xmlpull",
    "javax/xml",
];

const RETRO_GUARD_SETTING_COUNT: usize = 14;

pub const fn writer_loading_size() -> u64 {
    (RETRO_GUARD_DEFAULT_CFG.len()
        + RETRO_GUARD_SETTING_COUNT * 2 // Server + Client
        + IGNORE_PACKAGES.len() * 2) as u64
}

pub type RetroGuardResult = Result<(), RetroGuardError>;

#[derive(Debug)]
pub enum RetroGuardError {
    RetroGuardRuntimeError,
}

fn write_key_value(mut config_out: &File, key: &str, value: &str, config: &CommandArgConfig, mut progress_bar_mgr: &ActionProgressBarManager) {
    let processed_val = process_cfg_str(value, &config, None);

    config_out.write(format!("{} = {}\n", key, processed_val).as_bytes());
    progress_bar_mgr.inc_multi_bar();
}

fn create_retroguard_config(client: bool) -> HashMap<&str, &str> {
    let srg: &str = if client { SRG_CLIENT } else { SRG_SERVER };

    [
        ("startindex", "0"),
        ("input", if client { MINECRAFT_JAR } else { MINECRAFT_SERVER }),
        ("output", if client { RETRO_GUARD_CLIENT_OUT } else { RETRO_GUARD_SERVER_OUT }),
        ("reobinput", if client { RETRO_GUARD_CLIENT_RECOMP } else { RETRO_GUARD_SERVER_RECOMP }),
        ("reoboutput", if client { RETRO_GUARD_CLIENT_REOBF } else { RETRO_GUARD_SERVER_REOBF }),
        ("nplog", if client { RETRO_GUARD_CLIENT_DEOBF_LOG } else { RETRO_GUARD_SERVER_DEOBF_LOG }),
        ("rolog", if client { RETRO_GUARD_CLIENT_REOBF_LOG } else { RETRO_GUARD_SERVER_REOBF_LOG }),
        ("log", if client { RETRO_GUARD_CLIENT_LOG } else { RETRO_GUARD_SERVER_LOG }),
        ("reob", if client { RETRO_GUARD_CLIENT_OBF } else { RETRO_GUARD_SERVER_OBF }),
        ("script", RETRO_GUARD_CFG),
        ("packages", srg),
        ("classes", srg),
        ("methods", srg),
        ("fields", srg),
    ].iter().clone().collect()
}

pub fn write_retroguard_configs_once(config: &CommandArgConfig, progress_bar: ActionProgressBarManager) {
    lazy_static! {
        static ref made_configs: AtomicBool = AtomicBool::new(false);
    }

    if !made_configs.swap(true, Ordering::Relaxed) { return; }
    write_retroguard_configs(&config, progress_bar)
}

pub fn write_retroguard_configs(config: &CommandArgConfig, mut progress_bar_mgr: ActionProgressBarManager) {
    progress_bar_mgr.unwrap().message("Writing main config");

    let rg_config: String = process_cfg_str(RETRO_GUARD_CFG, &config, None);
    let mut rg_cfg_out: File = File::create(rg_config)?;

    for header in RETRO_GUARD_DEFAULT_CFG {
        rg_cfg_out.write(header.as_bytes());
        progress_bar.inc_multi_bar();
    }

    progress_bar_mgr.message("Writing client config");

    let client_config: HashMap<&str, &str> = create_retroguard_config(true);

    let rg_client_config: String = process_cfg_str(RETRO_GUARD_CLIENT_CFG, &config, None);
    let mut rg_client_cfg_out: File = File::create(rg_client_config)?;

    for (key, value) in client_config {
        write_key_value(&rg_client_cfg_out, key, value, &config, &progress_bar_mgr);
    }

    progress_bar_mgr.message("Writing server config");

    let server_config: HashMap<&str, &str> = create_retroguard_config(false);

    let rg_server_config: String = process_cfg_str(RETRO_GUARD_SERVER_CFG, &config, None);
    let mut rg_server_cfg_out: File = File::create(rg_server_config)?;

    for (key, value) in server_config {
        write_key_value(&rg_server_cfg_out, key, value, &config, &progress_bar_mgr);
    }

    progress_bar_mgr.message("Finishing up");

    for package in IGNORE_PACKAGES {
        let key: &str = "protectedpackage";

        write_key_value(&rg_client_cfg_out, key, package, &config, &progress_bar_mgr);
        write_key_value(&rg_server_cfg_out, key, package, &config, &progress_bar_mgr);

        progress_bar_mgr.tick();
    }

    progress_bar_mgr.finish( Some("✓ Finished Writing RetroGuard Configs"));
}

pub fn apply_retroguard(client: bool, config: &CommandArgConfig, mut progress_bar_mgr: &ActionProgressBarManager) -> RetroGuardResult {
    let rg_conf: &str = if client { RETRO_GUARD_CLIENT_CFG } else { RETRO_GUARD_SERVER_CFG };
    let class_path: &str = if client { RETRO_GUARD_CLIENT_CLASS_PATH } else { RETRO_GUARD_SERVER_CLASS_PATH };

    let jar_proc: String = process_cfg_str(RETRO_GUARD_JAR, &config, None);
    let rg_conf_proc: String = process_cfg_str(rg_conf, &config, None);
    let class_path_proc: String = process_cfg_str(class_path, &config, None);

    let rg_class_path: String = format!("{}{}{}", jar_proc, std::path::MAIN_SEPARATOR, class_path_proc);

    let cmd_proc: String = process_cfg_str(RETRO_GUARD_CMD, &config, None);
    let cmd_str: &str = format!(cmd_proc, class_path = rg_class_path, conf_file = rg_conf_proc).as_str();

    match exec_cmd(cmd_str, Some(&mut progress_bar_mgr)) {
        Ok(()) => { },
        Err(e) => {
            match e {
                ExecError::ExitCodeError { exit_code, exit_code_str } => {
                    error!("Retro Guard failed! With return code: {} : {}\nAdditional details can be found in the logs", exit_code, exit_code_str);
                }
            }

            Err(RetroGuardError::RetroGuardRuntimeError)
        }
    }

    Ok(())
}