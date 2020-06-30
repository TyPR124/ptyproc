use winapi::um::{
    namedpipeapi::CreatePipe,
    fileapi::{ReadFile, FlushFileBuffers, WriteFile},
    handleapi::{CloseHandle, DuplicateHandle},
    processthreadsapi::GetCurrentProcess,
    winnt::{DUPLICATE_SAME_ACCESS, HANDLE},
};

use winapi::shared::minwindef::FALSE;

use std::{
    ptr,
    io::{self, Read, Write},
    os::windows::io::{AsRawHandle, FromRawHandle},
};

fn last_error() -> io::Error { io::Error::last_os_error() }

pub struct Sender {
    handle: HANDLE,
}

pub struct Receiver {
    handle: HANDLE,
}

// Safety:
// Sender and Receiver's only purpose is to wrap a handle and call WriteFile and ReadFile, respectively.
// WriteFile and ReadFile are thread-safe, even if pipe is opened in synchronous mode and using non-overlapped
// operations.
unsafe impl Send for Sender {}
unsafe impl Sync for Sender {}
unsafe impl Send for Receiver {}
unsafe impl Sync for Receiver {}

impl Write for &Sender {
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
        let mut written: u32 = 0;
        let r = unsafe {
            WriteFile(self.handle, buf.as_ptr().cast(), buf.len() as u32, &mut written, ptr::null_mut())
        };
        if r == 0 {
            Err(last_error())?;
        }
        Ok(written as usize)
    }
}

impl Read for &Receiver {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut read: u32 = 0;
        let r = unsafe {
            ReadFile(self.handle, buf.as_mut_ptr().cast(), buf.len() as u32, &mut read, ptr::null_mut())
        };
        if r == 0 {
            Err(last_error())?;
        }
        Ok(read as usize)
    }
}

impl Write for Sender {
    fn flush(&mut self) -> io::Result<()> {
        (&*self).flush()
    }
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&*self).write(buf)
    }
}

impl Read for Receiver {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&*self).read(buf)
    }
}

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

impl Sender {
    /// Try to clone the Sender
    pub fn try_clone(&self) -> io::Result<Self> {
        let handle = try_clone_handle(self.handle)?;
        Ok(Self { handle })
    }
}

impl AsRawHandle for Sender {
    fn as_raw_handle(&self) -> *mut std::ffi::c_void {
        self.handle.cast()
    }
}

impl FromRawHandle for Sender {
    unsafe fn from_raw_handle(handle: *mut std::ffi::c_void) -> Self {
        Self { handle }
    }
}

impl Receiver {
    /// Try to clone the Receiver
    pub fn try_clone(&self) -> io::Result<Self> {
        let handle = try_clone_handle(self.handle)?;
        Ok(Self { handle })
    }
}

impl AsRawHandle for Receiver {
    fn as_raw_handle(&self) -> *mut std::ffi::c_void {
        self.handle.cast()
    }
}

impl FromRawHandle for Receiver {
    unsafe fn from_raw_handle(handle: *mut std::ffi::c_void) -> Self {
        Self { handle }
    }
}

fn try_clone_handle(handle: HANDLE) -> io::Result<HANDLE> {
    let proc = unsafe { GetCurrentProcess() };
    let mut new_handle = ptr::null_mut();
    let r = unsafe { DuplicateHandle(proc, handle, proc, &mut new_handle, 0 , FALSE, DUPLICATE_SAME_ACCESS) };
    if r == 0 {
        Err(last_error())?;
    }
    Ok(new_handle)
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

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    #[test]
    fn basic_pipe() {
        let (mut tx, mut rx) = super::unnamed().unwrap();
        let all_bytes= (0..=255).collect::<Vec<_>>();
        let mut out_buf = [0; 512];
        tx.write_all(&all_bytes).unwrap();
        assert_eq!(256, rx.read(&mut out_buf).unwrap());
        assert_eq!(&out_buf[..256], &all_bytes[..]);
    }
    
    #[test]
    fn pipe_writer_reader_threads() {
        let (mut tx, mut rx) = super::unnamed().unwrap();
        let all_bytes= (0..=255).collect::<Vec<_>>();
        let all_bytes2 = all_bytes.clone();
        let mut out_buf = Vec::new();
        let send = std::thread::spawn(move|| tx.write_all(&all_bytes2).unwrap());
        let recv = std::thread::spawn(move|| {
            let mut byte = [0];
            loop { match rx.read(&mut byte) {
                Ok(1) => out_buf.push(byte[0]),
                Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => break,
                Ok(n) => panic!("Expected to read 1 byte, got {}", n),
                res @ Err(_) => res.map(drop).unwrap(),
            }}
            out_buf
        });
        send.join().unwrap();
        assert_eq!(all_bytes, recv.join().unwrap());
    }

    #[test]
    fn threaded_pipe_multiple_writers_readers() {
        fn spawn_writers(n_threads: u8, mut tx: &'static super::Sender) -> Vec<std::thread::JoinHandle<()>> {
            assert!(n_threads > 1);
            let bytes_per_thread = (256 / n_threads as usize) as u8;
            let mut bufs = Vec::new();
            for i in 0..n_threads-1 {
                let v: Vec<u8> = ((i * bytes_per_thread)..((i+1)*bytes_per_thread)).collect();
                bufs.push(v);
            }
            let v: Vec<u8> = (((n_threads - 1) * bytes_per_thread)..=255).collect();
            bufs.push(v);

            bufs.into_iter().map(|buf| std::thread::spawn(move|| tx.write_all(&buf).unwrap())).collect()
        }
        fn spawn_readers(n_threads: u8, mut rx: &'static super::Receiver) -> Vec<std::thread::JoinHandle<Vec<u8>>> {
            let bufs = vec![Vec::with_capacity(256); n_threads as usize];

            bufs.into_iter().map(|mut buf| std::thread::spawn(move|| {
                let mut bytes = [0; 256];
                loop { match rx.read(&mut bytes) {
                    Ok(n) => buf.extend_from_slice(&bytes[..n]),
                    Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => break,
                    res @ Err(_) => res.map(drop).unwrap(),
                }}
                buf
            })).collect()
        }
        
        let all_bytes= (0..=255).collect::<Vec<_>>();

        for n_writers  in 2..=8 {
            for n_readers in 1..=8 {
                println!("testing with {} writers and {} readers", n_writers, n_readers);
                let (tx, rx) = super::unnamed().unwrap();
                let rx = Box::leak(Box::new(rx));
                let tx = Box::leak(Box::new(tx));
                let rx_ptr = rx as *mut _;
                let tx_ptr = tx as *mut _;

                let readers = spawn_readers(n_readers, rx);
                let writers = spawn_writers(n_writers, tx);

                for thread in writers { thread.join().unwrap() }
                drop(unsafe {
                    Box::from_raw(tx_ptr)
                });

                let mut final_buf = Vec::new();
                for (i, thread) in readers.into_iter().enumerate() {
                    let buf = thread.join().unwrap();
                    println!("thread {} had {} items", i, buf.len());
                    final_buf.extend(buf);
                }
                final_buf.sort_unstable();
                assert_eq!(final_buf, all_bytes);
                drop(unsafe { Box::from_raw(rx_ptr) } );
            }
        }
    }
    
    #[test]
    fn threaded_pipe_multiple_writers_readers_lots_of_data() {
        const TWO_MEGABYTES: usize = 2 * 1024 * 1024;

        fn spawn_writers(n_threads: u8, mut tx: &'static super::Sender) -> Vec<std::thread::JoinHandle<()>> {
            let mut bufs = Vec::new();
            for i in 0..n_threads {
                let v = vec![i; TWO_MEGABYTES];
                bufs.push(v);
            }

            bufs.into_iter().map(|buf| std::thread::spawn(move|| tx.write_all(&buf).unwrap())).collect()
        }
        fn spawn_readers(n_threads: u8, mut rx: &'static super::Receiver) -> Vec<std::thread::JoinHandle<Vec<u8>>> {
            let bufs = vec![Vec::with_capacity(256); n_threads as usize];

            bufs.into_iter().map(|mut buf| std::thread::spawn(move|| {
                let mut bytes = [0; 4096];
                loop { match rx.read(&mut bytes) {
                    Ok(n) => buf.extend_from_slice(&bytes[..n]),
                    Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => break,
                    res @ Err(_) => res.map(drop).unwrap(),
                }}
                buf
            })).collect()
        }

        let n_writers = 8;
        let n_readers = 8;
        println!("testing with {} writers and {} readers", n_writers, n_readers);
        let (tx, rx) = super::unnamed().unwrap();
        let rx = Box::leak(Box::new(rx));
        let tx = Box::leak(Box::new(tx));
        let rx_ptr = rx as *mut _;
        let tx_ptr = tx as *mut _;

        let readers = spawn_readers(n_readers, rx);
        let writers = spawn_writers(n_writers, tx);

        for thread in writers { thread.join().unwrap() }
        drop(unsafe {
            Box::from_raw(tx_ptr)
        });

        let mut final_buf = Vec::new();
        for (i, thread) in readers.into_iter().enumerate() {
            let buf = thread.join().unwrap();
            println!("thread {} had {} items", i, buf.len());
            final_buf.extend(buf);
        }
        drop(unsafe { Box::from_raw(rx_ptr) } );
        let mut counts = std::collections::HashMap::new();
        for x in final_buf {
            *counts.entry(x).or_insert(0usize) += 1;
        }
        let mut found = vec![false; n_writers as usize];
        for (id, count) in counts {
            if !found[id as usize] {
                println!("Found data from sender {}", id);
                found[id as usize] = true;
            }
            assert_eq!(count, TWO_MEGABYTES);
        }
        assert!(found.into_iter().all(|x| x));
    }

    #[test]
    fn pipe_clones() {
        {
            let (mut tx, mut rx) = super::unnamed().unwrap();
            drop(tx.try_clone().unwrap());
            drop(rx.try_clone().unwrap());
            let all_bytes= (0..=255).collect::<Vec<_>>();
            let mut out_buf = [0; 512];
            tx.write_all(&all_bytes).unwrap();
            assert_eq!(256, rx.read(&mut out_buf).unwrap());
            assert_eq!(&out_buf[..256], &all_bytes[..]);
            drop(tx);
            assert!(rx.read(&mut out_buf).is_err());
        }
        {
            let (mut tx, mut rx) = super::unnamed().unwrap();
            drop(tx.try_clone().unwrap());
            drop(rx.try_clone().unwrap());
            let all_bytes= (0..=255).collect::<Vec<_>>();
            let mut out_buf = [0; 512];
            tx.write_all(&all_bytes).unwrap();
            assert_eq!(256, rx.read(&mut out_buf).unwrap());
            assert_eq!(&out_buf[..256], &all_bytes[..]);
            drop(rx);
            assert!(tx.write(&out_buf).is_err());
        }
    }
}
