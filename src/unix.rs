use std;
use std::fs::File;
use std::process::{Command, ExitStatus};
use std::io;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::os::unix::io::{FromRawFd, AsRawFd};
use std::{thread, time};
use nix::pty::{posix_openpt, grantpt, unlockpt, PtyMaster};
use nix::fcntl::{OFlag, open};
use nix::sys::{stat, termios};
use nix::unistd::{fork, ForkResult, setsid, dup, dup2, Pid};
use nix::libc::{STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO};
pub use nix::sys::{wait, signal::{self, Signal}};

pub struct PtyProcess {
    pty: PtyMaster,
    pid: Pid,
    status: Option<ExitStatus>,
    drop_timeout: time::Duration,
}

#[cfg(target_os = "linux")]
use nix::pty::ptsname_r;

#[cfg(target_os = "macos")]
/// ptsname_r is a linux extension but ptsname isn't thread-safe
/// instead of using a static mutex this calls ioctl with TIOCPTYGNAME directly
/// based on https://blog.tarq.io/ptsname-on-osx-with-rust/
fn ptsname_r(fd: &PtyMaster) -> nix::Result<String> {
    use std::ffi::CStr;
    use nix::libc::{ioctl, TIOCPTYGNAME};

    // the buffer size on OSX is 128, defined by sys/ttycom.h
    let mut buf: [i8; 128] = [0; 128];

    unsafe {
        match ioctl(fd.as_raw_fd(), TIOCPTYGNAME as u64, &mut buf) {
            0 => {
                let res = CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned();
                Ok(res)
            }
            _ => Err(nix::Error::last()),
        }
    }
}

// Nix annoyingly wraps system errors, requiring a multi-step conversion
// including an unwrap :(
// This could be avoided by using libc directly, but that requires more unsafe.
// For any nix error created from nix::Error::last(), this function will never panic.
fn nix2io_err(err: nix::Error) -> std::io::Error {
    err.as_errno().unwrap().into()
}

fn spawn_pty(cmd: &mut Command) -> nix::Result<PtyProcess> {
    // Open a new PTY master
    let master_fd = posix_openpt(OFlag::O_RDWR)?;

    // Allow a slave to be generated for it
    grantpt(&master_fd)?;
    unlockpt(&master_fd)?;

    // on Linux this is the libc function, on OSX this is our implementation of ptsname_r
    let slave_name = ptsname_r(&master_fd)?;

    match fork()? {
        ForkResult::Child => {
            // create new session with child as session leader
            setsid()?;
            let slave_fd = open(std::path::Path::new(&slave_name),
                                OFlag::O_RDWR,
                                stat::Mode::empty())?;
        
            // assign stdin, stdout, stderr to the tty, just like a terminal does
            dup2(slave_fd, STDIN_FILENO)?;
            dup2(slave_fd, STDOUT_FILENO)?;
            dup2(slave_fd, STDERR_FILENO)?;

            // set echo off
            let mut flags = termios::tcgetattr(STDIN_FILENO)?;
            flags.local_flags &= !termios::LocalFlags::ECHO;
            termios::tcsetattr(STDIN_FILENO, termios::SetArg::TCSANOW, &flags)?;

            cmd.exec();
            Err(nix::Error::last())
        },
        ForkResult::Parent { child: pid } => {
            Ok(PtyProcess {
                pty: master_fd,
                pid,
                status: None,
                drop_timeout: time::Duration::from_secs(0),
            })
        }
    }
}

impl PtyProcess {
    pub fn spawn(cmd: &mut Command) -> std::io::Result<Self> {
        spawn_pty(cmd).map_err(nix2io_err)
    }
    pub fn id(&self) -> u32 {
        self.pid.as_raw() as u32
    }
    pub fn kill(&mut self) -> std::io::Result<()> {
        if self.status.is_some() {
            Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid argument: can't kill an exited process"))
        } else {
            signal::kill(self.pid, Signal::SIGKILL).map(drop).map_err(nix2io_err)
        }
    }
    pub fn wait(&mut self) -> std::io::Result<ExitStatus> {
        if let Some(status) = self.status {
            return Ok(status)
        }
        // There seems to be no good way to convert from nix WaitStatus to ExitStatus.
        // Therefore, falling back to libc
        let mut status = 0 as nix::libc::c_int;
        loop {
            if unsafe { nix::libc::waitpid(self.pid.as_raw(), &mut status, 0) } == -1 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue
                }
                return Err(err)
            }
            break
        }
        let status = ExitStatus::from_raw(status);
        self.status = Some(status);
        Ok(status)
    }
    pub fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        if let Some(status) = self.status {
            return Ok(Some(status))
        }
        let mut status = 0 as nix::libc::c_int;
        let _pid = match unsafe { nix::libc::waitpid(self.pid.as_raw(), &mut status, nix::libc::WNOHANG) } {
            -1 => return Err(io::Error::last_os_error()),
            0 => return Ok(None),
            pid => pid,
        };
        let status = ExitStatus::from_raw(status);
        self.status = Some(status);
        Ok(Some(status))
    }
    pub fn try_wait_timeout(&mut self, timeout: time::Duration) -> std::io::Result<Option<ExitStatus>> {
        let start = time::Instant::now();
        loop {
            if let Some(status) = self.try_wait()? {
                return Ok(Some(status))
            }
            if start.elapsed() > timeout {
                return Ok(None)
            }
        }
    }
    pub fn take_reader(&mut self) -> Option<File> {
        let fd = dup(self.pty.as_raw_fd()).unwrap();
        let file = unsafe { File::from_raw_fd(fd) };
        Some(file)
    }
    pub fn take_writer(&mut self) -> Option<File> {
        let fd = dup(self.pty.as_raw_fd()).unwrap();
        let file = unsafe { File::from_raw_fd(fd) };
        Some(file)
    }
    pub fn set_drop_timeout(&mut self, timeout: time::Duration) {
        self.drop_timeout = timeout;
    }
}

impl Drop for PtyProcess {
    fn drop(&mut self) {
        // Per docs on crate::PtyProcess::set_drop_timeout - send SIGTERM, wait for timeout, then SIGKILL
        if let Ok(None) = self.try_wait() {
            drop(signal::kill(self.pid, signal::Signal::SIGTERM));
            if let Ok(None) = self.try_wait_timeout(self.drop_timeout) {
                let res = self.kill();
                debug_assert!(res.is_ok(), "failed to kill PtyProcess");
                let res = self.wait();
                debug_assert!(res.is_ok(), "failed to cleanup PtyProcess");
            }
        }
    }
}
