use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(unix)] {
        use std::process::Command as InnerCommand;
        use crate::unix::PtyProcess as InnerPtyProcess;
        use std::fs::File as InnerPtyReader;
        use std::fs::File as InnerPtyWriter;
    } else if #[cfg(windows)] {
        use crate::windows::Command as InnerCommand;
        use crate::windows::PtyProcess as InnerPtyProcess;
        use crate::windows::pipe::Receiver as InnerPtyReader;
        use crate::windows::pipe::Sender as InnerPtyWriter;
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

static_assertions::assert_impl_all!(Command: Send, Unpin);
static_assertions::assert_not_impl_any!(Command: Sync);

static_assertions::assert_impl_all!(PtyProcess: Send, Unpin);
static_assertions::assert_not_impl_any!(PtyProcess: Sync);

static_assertions::assert_impl_all!(PtyReader: Read, Send, Unpin);
static_assertions::assert_not_impl_any!(PtyReader: Write, Sync);

static_assertions::assert_impl_all!(PtyWriter: Write, Send, Unpin);
static_assertions::assert_not_impl_any!(PtyWriter: Read, Sync);

/// A Command used to start a PtyProcess. Similar API as std's Command.
pub struct Command {
    pub(crate) inner: InnerCommand,
    _not_sync: PhantomData<std::cell::Cell<()>>,
}

impl Command {
    fn from_inner(inner: InnerCommand) -> Self {
        Self {
            inner,
            _not_sync: PhantomData,
        }
    }
    pub fn new<S: AsRef<OsStr>>(program: S) -> Command {
        Self::from_inner(InnerCommand::new(program))
    }
    pub fn arg<S: AsRef<OsStr>>(&mut self, arg: S) -> &mut Command {
        self.inner.arg(arg.as_ref());
        self
    }
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
    pub fn env<K, V>(&mut self, key: K, val: V) -> &mut Command
    where
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self.inner.env(key.as_ref(), val.as_ref());
        self
    }
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
    pub fn env_remove<K: AsRef<OsStr>>(&mut self, key: K) -> &mut Command {
        self.inner.env_remove(key.as_ref());
        self
    }
    pub fn env_clear(&mut self) -> &mut Command {
        self.inner.env_clear();
        self
    }
    pub fn current_dir<P: AsRef<Path>>(&mut self, dir: P) -> &mut Command {
        self.inner.current_dir(dir.as_ref());
        self
    }
    pub fn spawn_pty(&mut self) -> std::io::Result<PtyProcess> {
        PtyProcess::new(self)
    }
}

impl fmt::Debug for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

pub struct PtyProcess {
    inner: InnerPtyProcess,
    _not_sync: PhantomData<std::cell::Cell<()>>,
}

impl PtyProcess {
    fn from_inner(inner: InnerPtyProcess) -> Self {
        Self {
            inner,
            _not_sync: PhantomData
        }
    }
    pub fn new(cmd: &mut Command) -> std::io::Result<Self> {
        InnerPtyProcess::spawn(&mut cmd.inner).map(Self::from_inner)
    }
    pub fn id(&self) -> u32 {
        self.inner.id()
    }
    pub fn kill(&mut self) -> std::io::Result<()> {
        self.inner.kill()
    }
    pub fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        self.inner.try_wait()
    }
    /// Waits for a process to stop, returning if the timeout expires.
    /// 
    /// #Return
    /// 
    /// Returns Ok(Some(...)) if the process is halted before the timeout expires.
    /// Returns Ok(None) if the process is not halted before the timeout.
    /// Returns Err(...) only if an error occurs.
    pub fn try_wait_timeout(&mut self, timeout: time::Duration) -> std::io::Result<Option<ExitStatus>> {
        self.inner.try_wait_timeout(timeout)
    }
    pub fn wait(&mut self) -> std::io::Result<ExitStatus> {
        self.inner.wait()
    }
    pub fn take_reader(&mut self) -> Option<PtyReader> {
        self.inner.take_reader().map(PtyReader::from_inner)
    }
    pub fn take_writer(&mut self) -> Option<PtyWriter> {
        self.inner.take_writer().map(PtyWriter::from_inner)
    }
    // pub fn take_io_handles(&mut self) -> Option<(PtyReader, PtyWriter)> {
    //     let reader = self.take_reader()?;
    //     let writer = self.take_writer()?;
    //     Some((reader, writer))
    // }

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

pub struct PtyReader {
    inner: InnerPtyReader,
    _not_sync: PhantomData<std::cell::Cell<()>>,
}

impl PtyReader {
    fn from_inner(inner: InnerPtyReader) -> Self {
        Self {
            inner,
            _not_sync: PhantomData,
        }
    }
}

impl Read for PtyReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

pub struct PtyWriter {
    inner: InnerPtyWriter,
    _not_sync: PhantomData<std::cell::Cell<()>>,
}

impl PtyWriter {
    fn from_inner(inner: InnerPtyWriter) -> Self {
        Self {
            inner,
            _not_sync: PhantomData
        }
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
