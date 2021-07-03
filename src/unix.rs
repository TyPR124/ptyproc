use std;
use std::fs::File;
use std::process::{Command, ExitStatus};
use std::io::{self, Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::os::unix::io::{FromRawFd, AsRawFd};
use std::time;
use nix::pty::{posix_openpt, grantpt, unlockpt};
use nix::fcntl::{OFlag, open};
use nix::sys::{stat, termios};
use nix::unistd::{fork, ForkResult, setsid, dup, dup2, Pid};
use nix::libc::{STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO};
pub use nix::sys::{wait, signal::{self, Signal}};

pub struct PtyProcess {
    // reader and writer are both the same File object.
    // keeping them separate here allows us to avoid
    // a bit of unsafe code to make the PtyProcess::reader() and ::writer()
    // APIs work
    reader: crate::PtyReader,
    writer: crate::PtyWriter,
    pid: Pid,
    status: Option<ExitStatus>,
    drop_timeout: time::Duration,
}

pub trait PtyProcessExt {
    fn signal(&mut self, signal: impl Into<Option<Signal>>) -> nix::Result<()>;
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

    // The master_fd is more useful as a File. This fd is closed in same
    // way as any other fd, so we must effectively move the fd into a File
    // object without dropping (closing) the fd. Dup the fd for a reader and writer
    // pair.
    let (reader, writer) = {
        let fd1 = master_fd.as_raw_fd();
        std::mem::forget(master_fd);
        let fd2 = dup(fd1)?;
        unsafe { (File::from_raw_fd(fd1), File::from_raw_fd(fd2)) }
    };

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
                reader: crate::PtyReader::from_inner(reader),
                writer: crate::PtyWriter::from_inner(writer),
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
    pub fn reader(&self) -> &crate::PtyReader {
        &self.reader
    }
    pub fn writer(&self) -> &crate::PtyWriter {
        &self.writer
    }
    pub fn set_drop_timeout(&mut self, timeout: time::Duration) {
        self.drop_timeout = timeout;
    }
    pub fn signal(&mut self, signal: impl Into<Option<Signal>>) -> nix::Result<()> {
        if self.status.is_some() {
            // Process has already exited
            Err(nix::Error::invalid_argument())
        } else {
            signal::kill(self.pid, signal)
        }
    }
}

impl Read for &PtyProcess {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reader().read(buf)
    }
}

impl Read for PtyProcess {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        (&*self).read(buf)
    }
}

impl Write for &PtyProcess {
    fn flush(&mut self) -> std::io::Result<()> {
        self.writer().flush()
    }
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.writer().write(buf)
    }
}

impl Write for PtyProcess {
    fn flush(&mut self) -> std::io::Result<()> {
        (&*self).flush()
    }
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        (&*self).write(buf)
    }
}

impl Drop for PtyProcess {
    fn drop(&mut self) {
        // Per docs on crate::PtyProcess::set_drop_timeout - send SIGTERM, wait for timeout, then SIGKILL
        match self.try_wait() {
            Ok(Some(_)) => {}, // Process has ended
            _ => {
                let res = signal::kill(self.pid, signal::Signal::SIGTERM);
                debug_assert!(res.is_ok(), "failed to send SIGTERM");
                match self.try_wait_timeout(self.drop_timeout) {
                    Ok(Some(_)) => {}, // Process has ended
                    _ => {
                        let res = self.kill();
                        debug_assert!(res.is_ok(), "failed to kill PtyProcess");
                        let res = self.wait();
                        debug_assert!(res.is_ok());
                    }
                }
            }
        }
    }
}
