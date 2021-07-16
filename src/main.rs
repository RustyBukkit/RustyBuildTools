#[macro_use] extern crate lazy_static;
#[macro_use] extern crate log;

use std::borrow::Cow;
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{Write, Read};
use std::panic::resume_unwind;
use std::ptr::replace;

use clap::{App, Arg, ArgMatches, Clap, crate_authors, crate_description, crate_version};
use clap_conf::{Getter, with_toml_env};
use clap_conf::convert::{Holder, Localizer};
use clap_conf::env::Enver;
use clap_conf::grabber::Grabber;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use log::kv::Value;
use regex::{Captures, Regex};
use rust_embed::{Filenames, RustEmbed};
use simplelog::{ColorChoice, CombinedLogger, Config, LevelFilter, TerminalMode, TermLogger, WriteLogger};
use subprocess::{Exec, ExitStatus, Popen, PopenConfig, Redirection};
use winreg::RegKey;

use crate::actions::ActionProgressBarManager;
use crate::decompile::{EXCEPTOR_JAR, FF_JAR};
use crate::logging::ProgressLogger;
use crate::multi_progress_manager::ProgressBarManager;
use crate::retroguard::RETRO_GUARD_JAR;
use std::path::Path;
use md5::{Md5, Digest};
use md5::digest::DynDigest;
use md5::digest::generic_array::GenericArray;

pub mod lib;
pub mod logging;
pub mod multi_progress_manager;

pub mod actions;
pub mod decompile;
pub mod recompile;
pub mod retroguard;

const JAVA_VERSION: &str = "6"; // Yes, Java 6, because it was the best supported version for beta versions of minecraft and CraftBukkit

const TEMP_DIR: &str = "temp";
const LOGS_DIR: &str = "logs";
const BIN_DIR: &str = "bin";
const JARS_DIR: &str = "jars"; // Default jars dir for minecraft_server.jar, minecraft.jar, and natives/
const REOBF_OUT: &str = "%temp%/reobf";
const FF_OUT: &str = "%temp%/ff-out";
const RESOURCES_DIR: &str = "%temp%/resources";

const LOG_FILE: &str = "%logs%/rbt.log";

pub type ClapConf<'a> = Holder<'a, Holder<'a, Enver, &'a ArgMatches, String, &'a str>, Localizer<toml::Value>, String, String>;
pub type ClapConfGrabber<'b> = Grabber<'b, Self, R, Self::Iter>;

pub type ExecResult<'c> = Result<(), ExecError<'c>>;
pub type JavaCheckResult = Result<(), JavaCheckError>;

#[derive(Debug)]
pub enum ExecError<'d> {
    ExitCodeError { exit_code: u8, exit_code_str: &'d str },
}

#[derive(Debug)]
pub enum JavaCheckError {
    JavaMissingError,
    IncorrectJavaVersionError
}

#[derive(RustEmbed)]
#[folder = "resources/"]
pub struct Resources;

#[derive(RustEmbed)]
#[folder = "resources/extract"]
pub struct ResourcesExtract;

#[derive(RustEmbed)]
#[folder = "resources/bin"]
pub struct ResourcesBin;

pub struct CommandArgConfig<'e> {
    clap_conf: ClapConf<'e>,
    matches: ArgMatches,
}

impl CommandArgConfig {
    pub fn new(matches: ArgMatches) -> Self {
        let clap_conf: ClapConf = with_toml_env(&matches, &["config.toml"]);
        CommandArgConfig { clap_conf, matches, }
    }

    pub fn grab(&self) -> ClapConfGrabber {
        self.clap_conf.grab()
    }

    pub fn matches(&self) -> &ArgMatches {
        &self.matches
    }
}

fn main() {
    let matches: ArgMatches = App::new("RustyBuildTools")
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .arg(Arg::with_name("action")
            .short("a")
            .long("action")
            .takes_value(true)
            .value_name("ACTION(s)")
            .help("Specific action (or comma separated actions ran in order) to run alone"))
        .arg(Arg::with_name("bin dir")
            .short("b")
            .long("bin-dir")
            .takes_value(true)
            .value_name("DIR")
            .help("Bin directory holding distributed runtime binaries"))
        .arg(Arg::with_name("download client jar")
            .short("dlc")
            .long("dl-client")
            .help("If enabled, it will automatically fetch the proper minecraft.jar and natives from Mojang"))
        .arg(Arg::with_name("download server jar")
            .short("dls")
            .long("dl-server")
            .help("If enabled, it will automatically fetch the proper minecraft_server.jar from Mojang"))
        .arg(Arg::with_name("jars dir")
            .short("j")
            .long("jars-path")
            .takes_value(true)
            .value_name("DIR")
            .help("A directory containing the Minecraft Client and/or Server jars. (Will look for minecraft.jar, minecraft_server.jar, and natives/ in that directory)"))
        .arg(Arg::with_name("temp dir")
            .short("t")
            .long("temp-dir")
            .takes_value(true)
            .value_name("DIR")
            .help("Temp files directory path"))
        .arg(Arg::with_name("logs dir")
            .short("l")
            .long("logs-dir")
            .takes_value(true)
            .value_name("DIR")
            .help("Log files directory path"))
        .arg(Arg::with_name("fern flower decompile path")
            .short("ff")
            .long("ff-out-dir")
            .takes_value(true)
            .value_name("DIR")
            .help("Directory where decompiled sources from FernFlower will be put"))
        .arg(Arg::with_name("fern flower config")
            .short("fc")
            .long("ff-cfg")
            .takes_value(true)
            .value_name("PATH")
            .help("Commandline arguments to pass to FernFlower"))
        .arg(Arg::with_name("resources dir")
            .short("rd")
            .long("res-dir")
            .takes_value(true)
            .value_name("DIR")
            .help("Sets the resource dir of automatically extracted resources"))
        .arg(Arg::with_name("src client output")
            .short("scl")
            .long("src-client")
            .takes_value(true)
            .value_name("DIR")
            .help("SRC Output for MC Client"))
        .arg(Arg::with_name("src server output")
            .short("ssv")
            .long("src-server")
            .takes_value(true)
            .value_name("DIR")
            .help("SRC Output for MC Server"))
        .arg(Arg::with_name("src override")
            .short("SO")
            .long("src-override")
            .help("Will DELETE the src files when decompiling"))
        .arg(Arg::with_name("java home")
            .short("j")
            .long("java")
            .takes_value(true)
            .value_name("DIR")
            .help("Java Home directory (bin)"))
        .get_matches();

    let cfg: CommandArgConfig = CommandArgConfig::new(matches);

    println!("Extracting resources..");

    let resources_dir_proc: &str = process_cfg_str(RESOURCES_DIR, &cfg, None).as_str();
    let bin_dir_proc: &str = process_cfg_str(BIN_DIR, &cfg, None).as_str();

    // Write all embedded resources to local disk
    for file in ResourcesExtract::iter() {
        let file_str: &str = file.as_ref();
        let fl: Path = Path::new(file_str)?;

        let res_bytes: &[u8] = ResourcesExtract::get(fl).unwrap().as_ref();

        if fl.exists() {
            if fl.is_dir() {
                warn!("An embedded resource target was a directory! {}", file_str);
                return;
            }

            let mut hasher: Md5 = Md5::new();

            hasher.update(res_bytes);
            let our_result: Box<[u8]> = hasher.finalize_reset();

            let mut opened_file: File = File::open(file_str)?;
            let mut buf: Vec<u8> = Vec::new();

            opened_file.read_to_end(&mut buf)?;

            hasher.update(buf);
            let their_result: Box<[u8]> = hasher.finalize().to_vec().into_boxed_slice();

            debug!("MD5 of {} is {} and our version is {}", file_str, std::str::from_utf8(their_result)?, std::str::from_utf8(our_result)?);

            if our_result == their_result {
                continue;
            }
        }

        let mut file: File = File::create(format!("{}/{}", resources_dir_proc, file_str))?;
        file.write_all(res_bytes)?;
    }

    for file in ResourcesBin::iter() {
        let fl: &str = file.as_ref();
        let res_bytes: &[u8] = ResourcesExtract::get(fl).unwrap().as_ref();

        let mut file: File = File::create(format!("{}/{}", bin_dir_proc, fl))?;
        file.write_all(res_bytes)?;
    }

    println!("Checking java..");

    match check_java(&cfg) {
        Ok(()) => { },
        Err(e) => {
            match e {
                JavaCheckError::IncorrectJavaVersionError => {
                    println!("Java was found but it isn't the supported version. (You need Java {})", JAVA_VERSION);
                },
                JavaCheckError::JavaMissingError => {
                    println!("Java was not found! (You need Java {})", JAVA_VERSION);
                }
            };

            println!("You can download Azul's OpenJDK https://www.azul.com/downloads/?version=java-6-lts&package=jdk");
            println!("or officially from Oracle's archives page https://www.oracle.com/java/technologies/javase-java-archive-javase6-downloads.html");
            return;
        }
    }

    let log_file: String = process_cfg_str(LOG_FILE, &config, None);

    let mut multi_progress: MultiProgress = MultiProgress::new();

    let main_progress: ProgressBar = ProgressBar::new(0)
        .with_style(get_loading_style().clone())
        .with_message("Total Progress");

    CombinedLogger::init(
        vec![
            ProgressLogger::new(LevelFilter::Warn, Config::default(), &main_progress),
            WriteLogger::new(LevelFilter::Info, Config::default(), OpenOptions::new().append(true).open(log_file)),
        ]
    );


}

/**
 * Parses %temp% and etc to their configured values
 */
pub fn process_cfg_str(path: &str, config: &CommandArgConfig, iterations: Option<u8>) -> String {
    lazy_static!(
        static ref rgx: Regex = Regex::new(r"%(?P<var>\w+)%").unwrap();
    );

    rgx.replace_all(path, |captures: Captures| {
        captures.name("var").map(|var| -> String {
            let str_var: &str = var.as_str();

            let result: String = match str_var {
                "bin" => config.grab().arg("bin dir").conf("bin-dir").def(BIN_DIR),
                "temp" => config.grab().arg("temp dir").conf("temp-dir").def(TEMP_DIR),
                "logs" => config.grab().arg("logs dir").conf("logs-dir").def(LOGS_DIR),
                "jars" => config.grab().arg("jars dir").conf("logs-dir").def(LOGS_DIR),
                "ff-out" => config.grab().arg("fern flower decompile path").conf("ff-out-dir").def(FF_OUT),
                "resources" => config.grab().arg("resources dir").conf("resource-dir").def(RESOURCES_DIR),

                "retro_guard_jar" => RETRO_GUARD_JAR,
                "exceptor_jar" => EXCEPTOR_JAR,
                "ff_jar" => FF_JAR,
                &_ => "",
            };

            let i: u8 = match iterations {
                Some(i) => i,
                None => 0,
            };

            if i < 10 && rgx.is_match(result.as_str()) {
                process_cfg_str(result.as_str(), &config, Some(i + 1))
            }

            result
        }).unwrap()
    }).into_owned()
}

pub fn check_java(config: &CommandArgConfig) -> JavaCheckResult {
    let os: &str = env::consts::OS;
    let cmd: &str = match os {
        "windows" => "{} 1>NUL 2>NUL",
        _ => "{} 1> /dev/null 2> /dev/null",
    };

    let mut try_paths: Vec<&str> = Vec::new();

    config.grab().arg("java home").conf("java-home").done().and_then(|java_home| {
        try_paths.push(java_home);
        Some(java_home)
    });

    match os {
        "windows" => {
            let reg = RegKey::predef(winreg::enums::KEY_WOW64_64KEY);
            let jdk_key = format!("Software\\JavaSoft\\Java Development Kit\\1.{}", JAVA_VERSION);
            let sub_key = reg.open_subkey(jdk_key)?;
            let java_path = sub_key.get_value("JavaHome")?;

            try_paths.push(format!("{}\\{}", java_path, "java.exe").as_str());
            try_paths.push("java.exe");
        },
        _ => {
            try_paths.push("/usr/bin/java");
            try_paths.push("/usr/local/bin/java");
            try_paths.push("java");
        },
    };

    let mut java_found: bool = false;

    for path in try_paths {
        let exit: ExitStatus = Exec::shell(format!(cmd, path)).join()?;

        if exit == 2 {
            java_found = true;

            let v_check_cmd: String =
                format!("{} -version 2>&1 | head -1 | cut -d'\"' -f2 | sed '/^1\\./s///' | cut -d'.' -f1", path);

            if Exec::shell(v_check_cmd).capture()?.stdout_str() != JAVA_VERSION {
                continue;
            }

            Ok(())
        }
    }

    if java_found {
        Err(JavaCheckError::IncorrectJavaVersionError)
    }

    Err(JavaCheckError::JavaMissingError)
}

pub fn get_loading_style() -> ProgressStyle {
    ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] {wide_bar:.cyan/blue} ({percent})")
}

pub fn get_dl_loading_style() -> ProgressStyle {
    ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] {wide_bar:.cyan/blue} [{bytes}/{total_bytes}] {binary_bytes_per_sec} ({percent})")
}

pub fn exec_cmd(cmd_str: &str, progress_bar_mgr: Option<&mut ActionProgressBarManager>) -> ExecResult {
    let mut pipe: Popen = Popen::create(cmd_str, PopenConfig {
        stdout: Redirection::Pipe, ..Default::default()
    })?;

    let mut buffer_lines: Vec<&str> = Vec::new();
    let mut ret_code: Option<ExitStatus> = None;

    loop {
        let o: &str = pipe.stdout.unwrap()?;
        ret_code: Option<ExitStatus> = pipe.poll();

        if ret_code.is_some() && o == "" {
            break;
        } else {
            buffer_lines.push(o.trim());
        }

        progress_bar_mgr.unwrap().tick();
    }

    for line in buffer_lines {
        debug!(line);
    }

    if ret_code.unwrap() != 0 {
        let ret_code_str: &str = ret_code.map_or_else(|| "None", |code| code.into());
        Err(ExecError::ExitCodeError { exit_code: ret_code.unwrap().into(), exit_code_str: ret_code_str })
    }

    Ok(())
}