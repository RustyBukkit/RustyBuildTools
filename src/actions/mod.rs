use std::error::Error;

use indicatif::{MultiProgress, ProgressBar};

use crate::CommandArgConfig;
use crate::multi_progress_manager::ProgressBarManager;

pub type ActionResult = Result<(), dyn Error>;

pub trait Action {
    fn do_action(&self, config: &CommandArgConfig) -> ActionResult;
    fn create_multi_bars(&self, config: &CommandArgConfig, multi_bar: &MultiProgress) -> usize;
    fn get_total_progress(&self) -> &ProgressBar;
}

pub struct ActionProgressBarManager<'a> {
    action: Option<&'a dyn Action>,
    progress_bar: Option<&'a ProgressBar>,
}

impl ActionProgressBarManager {
    fn new(action: &dyn Action, progress_bar: Option<&ProgressBar>) -> Self {
        ActionProgressBarManager { action: Some(action), progress_bar }
    }

    fn empty() -> Self {
        ActionProgressBarManager { action: None, progress_bar: None }
    }
}

impl ProgressBarManager for ActionProgressBarManager {
    fn get_progress_bar(&self) -> Option<&ProgressBar> {
        self.progress_bar
    }

    fn tick(&mut self) -> bool {
        if self.progress_bar.is_none() {
            false
        }

        self.progress_bar.unwrap().tick();
        true
    }

    fn inc_multi_bar(&mut self) -> bool {
        if self.progress_bar.is_none() {
            false
        }

        self.progress_bar.unwrap().inc(1);

        if self.action.is_none() || progress_bar == self.action.unwrap().get_total_progress() {
            true
        }

        self.action.unwrap().get_total_progress().inc(1);
        true
    }

    fn message(&mut self, message: &str) -> bool {
        if self.progress_bar.is_none() {
            false
        }

        self.progress_bar.unwrap().set_message(message);
        true
    }

    fn finish(&mut self, message: Option<&str>) -> bool {
        if self.progress_bar.is_none() {
            false
        }

        match message {
            Some(msg) => self.progress_bar.unwrap().finish_with_message(msg),
            None => self.progress_bar.unwrap().finish(),
        };
        true
    }
}