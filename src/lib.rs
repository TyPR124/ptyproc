#![cfg_attr(windows, feature(osstring_ascii))]
//! TODO: Library Docs
//! 



#[cfg(unix)]
mod unix;

#[cfg(windows)]
mod windows;

#[cfg(test)]
mod tests;

mod wrappers;
pub use wrappers::{Command, PtyProcess, PtyReader, PtyWriter};

pub mod os {
    #[cfg(unix)]
    pub mod unix {
        pub use crate::unix::PtyProcessExt;
    }
}
