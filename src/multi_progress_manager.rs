use indicatif::ProgressBar;

pub trait ProgressBarManager {
    fn get_progress_bar(&self) -> Option<&ProgressBar>;

    // Alias functions
    fn tick(&mut self) -> bool;
    fn inc_multi_bar(&mut self) -> bool;
    fn message(&mut self, message: &str) -> bool;
    fn finish(&mut self, message: Option<&str>) -> bool;
}