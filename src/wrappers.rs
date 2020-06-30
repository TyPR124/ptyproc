cfg_if::cfg_if! {
    if #[cfg(unix)] {
        use std::process::Command as InnerCommand;
        use crate::unix::PtyProcess as InnerPtyProcess;
        use std::fs::File as InnerPtyReader;
        use std::fs::File as InnerPtyWriter;
        use std::os::unix::io::{AsRawFd, RawFd};
        use nix::sys::signal::Signal;
    } else if #[cfg(windows)] {
        use crate::windows::Command as InnerCommand;
        use crate::windows::PtyProcess as InnerPtyProcess;
        use crate::windows::pipe::Receiver as InnerPtyReader;
        use crate::windows::pipe::Sender as InnerPtyWriter;
        use std::os::windows::io::{AsRawHandle, RawHandle};
    }
}

use std::{
    ffi::OsStr,
    fmt,
    path::Path,
    process::ExitStatus,
    io::{Read, Write},
    marker::PhantomData,
    time,
};

// Assertions over trait impls to ensure common behavior on all platforms
static_assertions::assert_impl_all!(Command: Send, Unpin);
static_assertions::assert_not_impl_any!(Command: Sync);

static_assertions::assert_impl_all!(PtyProcess: Read, Write, Send, Sync, Unpin);
static_assertions::assert_impl_all!(PtyReader: Read, Send, Sync, Unpin);
static_assertions::assert_impl_all!(PtyWriter: Write, Send, Sync, Unpin);

/// A Command used to start a PtyProcess. Similar API as std's Command.
pub struct Command {
    pub(crate) inner: InnerCommand,
    // std::process::Command (used by unix) is not Sync.
    // This ensures our Command is not Sync on Windows.
    _not_sync: PhantomData<std::cell::Cell<()>>,
}

/// A PtyProcess represents a process which is using a PseudoTerminal to handle IO.
///
/// The child process and pseudoterminal are destroyed when this object is dropped.
/// A timeout can be configured to wait for the process to end before returning from drop.
/// See PtyProcess::set_drop_timeout
pub struct PtyProcess {
    inner: InnerPtyProcess,
}

impl Command {
    fn from_inner(inner: InnerCommand) -> Self {
        Self {
            inner,
            _not_sync: PhantomData,
        }
    }
    /// Creates a new Command with the specified program. Same as std's Command::new
    pub fn new<S: AsRef<OsStr>>(program: S) -> Command {
        Self::from_inner(InnerCommand::new(program))
    }
    /// Appends an argument to the Command to be executed. Same as std's Command::arg
    pub fn arg<S: AsRef<OsStr>>(&mut self, arg: S) -> &mut Command {
        self.inner.arg(arg.as_ref());
        self
    }
    /// Appends multiple arguments to the Command to be executed. Same as std's Command::args
    pub fn args<I, S>(&mut self, args: I) -> &mut Command
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        for arg in args {
            self.arg(arg.as_ref());
        }
        self
    }
    /// Sets an environment variable which will be visible to the child process. Same as std's Command::env
    pub fn env<K, V>(&mut self, key: K, val: V) -> &mut Command
    where
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self.inner.env(key.as_ref(), val.as_ref());
        self
    }
    /// Sets multiple environment variables which will be visible to the child process. Same as std's Command::envs
    pub fn envs<I, K, V>(&mut self, vars: I) -> &mut Command
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        for (ref key, ref val) in vars {
            self.env(key.as_ref(), val.as_ref());
        }
        self
    }
    /// Removes an environment variable from the child process's view. Same as std's Command::env_remove
    pub fn env_remove<K: AsRef<OsStr>>(&mut self, key: K) -> &mut Command {
        self.inner.env_remove(key.as_ref());
        self
    }
    /// Remove all environment variables from the child process's view. Same as std's Command::env_clear
    pub fn env_clear(&mut self) -> &mut Command {
        self.inner.env_clear();
        self
    }
    /// Sets the initial current working directory for the child process. Same as std's Command::current_dir
    pub fn current_dir<P: AsRef<Path>>(&mut self, dir: P) -> &mut Command {
        self.inner.current_dir(dir.as_ref());
        self
    }
    /// Spawns the process in a new Pseudoterminal.
    pub fn spawn_pty(&mut self) -> std::io::Result<PtyProcess> {
        PtyProcess::new(self)
    }
}

impl fmt::Debug for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

impl PtyProcess {
    fn from_inner(inner: InnerPtyProcess) -> Self {
        Self {
            inner,
        }
    }
    /// Spawns a new PtyProcess using the provided Command.
    pub fn new(cmd: &mut Command) -> std::io::Result<Self> {
        InnerPtyProcess::spawn(&mut cmd.inner).map(Self::from_inner)
    }
    /// Returns the Process ID of the child process.
    pub fn id(&self) -> u32 {
        self.inner.id()
    }
    /// Immediately and forcibly terminate the child process.
    pub fn kill(&mut self) -> std::io::Result<()> {
        self.inner.kill()
    }
    /// Attempt to wait for the process to stop without blocking.
    pub fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        self.inner.try_wait()
    }
    /// Attempt to wait for the process to stop, blocking up to the timeout before returning.
    pub fn try_wait_timeout(&mut self, timeout: time::Duration) -> std::io::Result<Option<ExitStatus>> {
        self.inner.try_wait_timeout(timeout)
    }
    /// Attempt to wait for the process to stop, blocking as long as is required.
    pub fn wait(&mut self) -> std::io::Result<ExitStatus> {
        self.inner.wait()
    }
    /// Attempt to clone the PtyReader from this process.
    pub fn try_clone_reader(&self) -> std::io::Result<PtyReader> {
        self.inner.try_clone_reader().map(PtyReader::from_inner)
    }
    /// Attempt to clone the PtyWriter from this process.
    pub fn try_clone_writer(&self) -> std::io::Result<PtyWriter> {
        self.inner.try_clone_writer().map(PtyWriter::from_inner)
    }

    /// Setting this value changes the behavior of dropping the PtyProcess. The default timeout value is 0.
    ///
    /// If this value is 0, when the PtyProcess is dropped the underlying process is immediately killed if
    /// it is has not exited already.
    ///
    /// If this value is non-zero, on Unix the child process is sent a SIGTERM signal, then waited up to the timeout.
    /// If the process has not stopped by then, it is killed with SIGKILL. On Windows, the process is waited up to the
    /// timeout to stop on its own, then it is terminated.
    pub fn set_drop_timeout(&mut self, timeout: time::Duration) {
        self.inner.set_drop_timeout(timeout)
    }
}

impl Read for &PtyProcess {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        (&self.inner).read(buf)
    }
}

impl Write for &PtyProcess {
    fn flush(&mut self) -> std::io::Result<()> {
        (&self.inner).flush()
    }
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        (&self.inner).write(buf)
    }
}

impl Read for PtyProcess {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        (&*self).read(buf)
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

pub struct PtyReader {
    inner: InnerPtyReader,
}

impl PtyReader {
    fn from_inner(inner: InnerPtyReader) -> Self {
        Self {
            inner,
        }
    }
    pub fn try_clone(&self) -> std::io::Result<Self> {
        let cloned = self.inner.try_clone()?;
        Ok(Self::from_inner(cloned))
    }
}

impl Read for PtyReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}
pub struct PtyWriter {
    inner: InnerPtyWriter,
}

impl PtyWriter {
    fn from_inner(inner: InnerPtyWriter) -> Self {
        Self {
            inner,
        }
    }
    pub fn try_clone(&self) -> std::io::Result<Self> {
        let cloned = self.inner.try_clone()?;
        Ok(Self::from_inner(cloned))
    }
}

impl Write for PtyWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(unix)]
impl AsRawFd for PtyReader {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

#[cfg(unix)]
impl AsRawFd for PtyWriter {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

#[cfg(windows)]
impl AsRawHandle for PtyReader {
    fn as_raw_handle(&self) -> RawHandle {
        self.inner.as_raw_handle()
    }
}

#[cfg(windows)]
impl AsRawHandle for PtyWriter {
    fn as_raw_handle(&self) -> RawHandle {
        self.inner.as_raw_handle()
    }
}

#[cfg(unix)]
impl crate::os::unix::PtyProcessExt for crate::PtyProcess {
    fn signal(&mut self, signal: impl Into<Option<Signal>>) -> nix::Result<()> {
        self.inner.signal(signal)
    }
}
