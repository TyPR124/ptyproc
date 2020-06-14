use winapi::um::{
    namedpipeapi::CreatePipe,
    fileapi::{ReadFile, FlushFileBuffers, WriteFile},
    handleapi::CloseHandle,
    winnt::HANDLE,
};

use std::{
    ptr,
    io::{self, Read, Write},
    // os::windows::io::AsRawHandle,
};

fn last_error() -> io::Error { io::Error::last_os_error() }

pub struct Sender {
    handle: HANDLE,
}

pub struct Receiver {
    handle: HANDLE,
}

// Send is safe iff Sender and Receiver cannot
// be duplicated in any (safe) way. All Reads
// and Writes are blocking operations.
unsafe impl Send for Sender {}
unsafe impl Send for Receiver {}

impl Drop for Sender {
    fn drop(&mut self) {
        let r = unsafe { CloseHandle(self.handle) };
        debug_assert_ne!(0, r);
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        let r = unsafe { CloseHandle(self.handle) };
        debug_assert_ne!(0, r);
    }
}

impl Write for Sender {
    fn flush(&mut self) -> io::Result<()> {
        let r = unsafe {
            FlushFileBuffers(self.handle)
        };
        if r == 0 {
            Err(io::Error::last_os_error())?;
        }
        Ok(())
    }
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut written = 0;
        let r = unsafe {
            WriteFile(self.handle, buf.as_ptr().cast(), buf.len() as u32, &mut written, ptr::null_mut())
        };
        if r == 0 {
            Err(last_error())?;
        }
        Ok(written as usize)
    }
}

impl Read for Receiver {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut read = 0;
        let r = unsafe {
            ReadFile(self.handle, buf.as_mut_ptr().cast(), buf.len() as u32, &mut read, ptr::null_mut())
        };
        if r == 0 {
            Err(last_error())?;
        }
        Ok(read as usize)
    }
}

impl Sender {
    pub fn as_raw_handle(&self) -> HANDLE {
        self.handle
    }
}

impl Receiver {
    pub fn as_raw_handle(&self) -> HANDLE {
        self.handle
    }
}

pub fn unnamed() -> io::Result<(Sender, Receiver)> {
    let mut tx: HANDLE = ptr::null_mut();
    let mut rx: HANDLE = ptr::null_mut();
    let r = unsafe {
        CreatePipe(&mut rx, &mut tx, ptr::null_mut(), 0)
    };
    if r == 0 {
        Err(last_error())?;
    }
    let tx = Sender { handle: tx };
    let rx = Receiver { handle: rx };
    Ok((tx, rx))
}
