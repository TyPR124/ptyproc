#![cfg_attr(windows, feature(osstring_ascii))]

#[cfg(unix)]
mod unix;

#[cfg(windows)]
mod windows;

mod wrappers;
pub use wrappers::{Command, PtyProcess, PtyReader, PtyWriter};
