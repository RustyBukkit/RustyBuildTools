use std::borrow::Cow;
use std::sync::Mutex;
use std::thread;

use chrono::format::{DelayedFormat, StrftimeItems};
use indicatif::ProgressBar;
use log::{Level, Log, Metadata, Record, set_boxed_logger, set_max_level, SetLoggerError};
use simplelog::{Config, LevelFilter, LevelPadding, SharedLogger, ThreadLogMode, ThreadPadding};

pub struct ProgressLogger<'a> {
    level: LevelFilter,
    config: Config,
    progress_bar: &'a ProgressBar,
}

impl ProgressLogger {
    pub fn init(log_level: LevelFilter, config: Config, progress_bar: &ProgressBar) -> Result<(), SetLoggerError> {
        set_max_level(log_level);
        set_boxed_logger(ProgressLogger::new(log_level, config, progress_bar))
    }

    pub fn new(log_level: LevelFilter, config: Config, progress_bar: &ProgressBar) -> Box<ProgressLogger> {
        Box::new(ProgressLogger {
            level: log_level,
            progress_bar,
            config,
        })
    }
}

impl Log for ProgressLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let mut log_str: String = String::new();

        let level: Level = record.level();

        if self.config.time <= level && self.config.time != LevelFilter::Off {
            let time = if self.config.time_local
            { chrono::Local::now() } else { chrono::Utc::now() };
            let cur_time: DelayedFormat<StrftimeItems> =
                (time + self.config.time_offset).format(&*self.config.time_format);

            log_str.push_str(format!("{} ", cur_time).as_str())
        }

        if self.config.level <= level && self.config.level != LevelFilter::Off {
            let level_fmt: &str = match config.level_padding {
                LevelPadding::Left => "[{: >5}] ",
                LevelPadding::Right => "[{: <5}] ",
                LevelPadding::Off => "[{}] ",
            };

            log_str.push_str(format!(level_fmt, level).as_str());
        }

        if self.config.thread <= level && self.config.thread != LevelFilter::Off {
            let thread_fmt: &str = match self.config.thread_padding {
                ThreadPadding::Left { 0: qty } => "({id:>" + qty + "}) ",
                ThreadPadding::Right { 0: qty } => "({id:>" + qty + "}) ",
                ThreadPadding::Off => "({id}) ",
            };

            fn log_id(thread_fmt: &str, log_str: &mut String) {
                let id = format!("{:?}", thread::current().id())
                    .replace("ThreadId(", "").replace(")", "");
                log_str.push_str(format!(thread_fmt, id = id).as_str());
            }

            fn log_name(thread_fmt: &str, log_str: &mut String) {
                let name: Option<&str> = thread::current().name();

                if name.is_some() {
                    log_str.push_str(format!(thread_fmt, id = name.unwrap()).as_str());
                }
            }

            match self.config.thread_log_mode {
                ThreadLogMode::IDs => {
                    log_id(thread_fmt, &mut log_str);
                },
                ThreadLogMode::Names => {
                    log_name(thread_fmt, &mut log_str);
                },
                ThreadLogMode::Both => {
                    log_id(thread_fmt, &mut log_str);
                    log_name(thread_fmt, &mut log_str);
                },
            }
        }

        if self.config.target <= level && self.config.target != LevelFilter::Off {
            log_str.push_str(format!("{}: ", record.target()).as_str());
        }

        if self.config.location <= level && self.config.location != LevelFilter::Off {
            let file = record.file().unwrap_or("<unknown>");
            let line = record.line().map_or_else(|| "<unknown>", |line| {
                line.to_string().as_str()
            });

            log_str.push_str(format!("[{}:{}] ", file, line).as_str());
        }

        log_str.push_str(record.args().as_str().unwrap_or(""));

        self.progress_bar.println(log_str);
    }

    fn flush(&self) { }
}

impl SharedLogger for ProgressLogger {
    fn level(&self) -> LevelFilter {
        self.level
    }

    fn config(&self) -> Option<&Config> {
        Some(&self.config)
    }

    fn as_log(self: Box<Self>) -> Box<dyn Log> {
        Box::new(*self)
    }
}