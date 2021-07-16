/**
 * Zip-Extract by MCOfficer
 * *
 * Licensed under MIT - https://github.com/MCOfficer/zip-extract
 *
 * Modified by LittleBigBug (Progress bars, that's it)
 */

#![forbid(unsafe_code)]

#[macro_use]
extern crate log;

use std::{fs, io};
use std::io::{Read, Seek};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{PathBuf, StripPrefixError};
use thiserror::Error;

/// Re-export of zip's error type, for convenience.
///
pub use zip::result::ZipError;
use crate::multi_progress_manager::ProgressBarManager;

pub type ZipExtractResult = Result<(), ZipExtractError>;

/// zip-extract's error type
#[derive(Error, Debug)]
pub enum ZipExtractError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Zip(#[from] ZipError),
    #[error("Failed to strip toplevel directory {} from {}: {error}", .toplevel.to_string_lossy(), .path.to_string_lossy())]
    StripToplevel {
        toplevel: PathBuf,
        path: PathBuf,
        error: StripPrefixError,
    },
}

/// Extracts a zip archive into `target_dir`.
///
/// `target_dir` is created if it doesn't exist. Will error if `target_dir.parent()` doesn't exist.
///
/// If `strip_toplevel` is true, will strip away the topmost directory. `strip_toplevel` only applies
/// if all files and directories within the archive are descendants of the toplevel directory.
///
/// If you want to read from a source that doesn't implement Seek, you can wrap it into a Cursor:
/// ```
/// use std::io::Cursor;
/// use std::path::PathBuf;
///
/// let bytes: Vec<u8> = vec![];
/// let target = PathBuf::from("/tmp/target-directory");
/// zip_extract::extract(Cursor::new(bytes), &target, false);
/// ```
///
/// If on unix, `extract` will preserve permissions while extracting.

pub fn extract<S: Read + Seek>(
    source: S,
    target_dir: &PathBuf,
    strip_toplevel: bool,
) -> Result<(), ZipExtractError> {
    extract_progress(source, target_dir, strip_toplevel, None)
}

/// Optionally ProgressBarManager to call ticks

pub fn extract_progress<S: Read + Seek>(
    source: S,
    target_dir: &PathBuf,
    strip_toplevel: bool,
    progress_bar: Option<dyn ProgressBarManager>,
) -> Result<(), ZipExtractError> {
    if !target_dir.exists() {
        fs::create_dir(&target_dir)?;
    }

    let mut archive = zip::ZipArchive::new(source)?;

    let do_strip_toplevel = strip_toplevel && has_toplevel(&mut archive)?;

    debug!("Extracting to {}", target_dir.to_string_lossy());
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let mut relative_path = PathBuf::from(file.enclosed_name().unwrap());

        if do_strip_toplevel {
            let base = relative_path
                .components()
                .take(1)
                .fold(PathBuf::new(), |mut p, c| {
                    p.push(c);
                    p
                });
            relative_path = relative_path
                .strip_prefix(&base)
                .map_err(|error| ZipExtractError::StripToplevel {
                    toplevel: base,
                    path: relative_path.clone(),
                    error,
                })?
                .to_path_buf()
        }

        if relative_path.to_string_lossy().is_empty() {
            // Top-level directory
            continue;
        }

        let mut outpath = target_dir.clone();
        outpath.push(relative_path);

        trace!(
            "Extracting {} to {}",
            file.name(),
            outpath.to_string_lossy()
        );
        if file.name().ends_with('/') {
            fs::create_dir_all(&outpath)?;
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    fs::create_dir_all(&p)?;
                }
            }
            let mut outfile = fs::File::create(&outpath)?;
            io::copy(&mut file, &mut outfile)?;
        }

        #[cfg(unix)]
            set_unix_mode(&file, &outpath)?;

        if progress_bar.is_some() {
            progress_bar.unwrap().tick();
        }
    }

    debug!("Extracted {} files", archive.len());
    Ok(())
}

fn has_toplevel<S: Read + Seek>(
    archive: &mut zip::ZipArchive<S>,
) -> Result<bool, zip::result::ZipError> {
    let mut toplevel_dir: Option<PathBuf> = None;
    if archive.len() < 2 {
        return Ok(false);
    }

    for i in 0..archive.len() {
        let file = archive.by_index(i)?.enclosed_name().unwrap();
        if let Some(toplevel_dir) = &toplevel_dir {
            if !file.starts_with(toplevel_dir) {
                trace!("Found different toplevel directory");
                return Ok(false);
            }
        } else {
            // First iteration
            let comp: PathBuf = file.components().take(1).collect();
            trace!(
                "Checking if path component {} is the only toplevel directory",
                comp.to_string_lossy()
            );
            toplevel_dir = Some(comp);
        }
    }
    trace!("Found no other toplevel directory");
    Ok(true)
}

#[cfg(unix)]
fn set_unix_mode(file: &zip::read::ZipFile, outpath: &PathBuf) -> io::Result<()> {
    if let Some(m) = file.unix_mode() {
        fs::set_permissions(&outpath, PermissionsExt::from_mode(m))?
    }
    Ok(())
}
