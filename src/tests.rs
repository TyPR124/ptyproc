use crate::Command;
use std::io::{Read, Write};

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        const CAT: &str = "cat";
        const CAT_ARGS: &[&str] = &[];
        const SHELL: &str = "bash";
    } else if #[cfg(windows)] {
        const CAT: &str = "cmd";
        const CAT_ARGS: &[&str] = &["/C", "type"];
        const SHELL: &str = "cmd";
    }
}

const ONE_SECOND: std::time::Duration = std::time::Duration::from_secs(1);

#[test]
fn test_show_file_contents() {
    const DATA: &str = "testing echo file contents";
    let f = {
        let mut f = tempfile::NamedTempFile::new().expect("failed to create tempfile");
        write!(f, "{}", DATA).expect("failed to write to tempfile");
        f
    };
    let mut p = Command::new(CAT).args(CAT_ARGS).arg(f.path()).spawn_pty().unwrap();
    std::thread::sleep(ONE_SECOND);
    let mut buf = [0; 1024];
    p.read(&mut buf[..]).expect("Failed to read from pty process");
    let s = String::from_utf8_lossy(&buf[..]);
    assert!(s.contains(DATA));
    p.try_wait().expect("failed to try_wait").expect("failed to get exit status");
}
#[test]
fn test_echo_in_shell() {
    let mut p = Command::new(SHELL).spawn_pty().unwrap();
    let bytes = b"echo Hello, World!\r\n";
    p.write_all(bytes).expect("Failed to write to process");
    std::thread::sleep(ONE_SECOND);
    let mut buf = [0; 1024];
    p.read(&mut buf[..]).expect("Failed to read from process");
    let s = String::from_utf8_lossy(&buf[..]);
    assert_eq!(2, s.lines().filter(|s| s.contains("Hello, World")).count());
    let bytes = b"exit\r\n";
    p.write_all(bytes).expect("Failed to write exit to process");
    std::thread::sleep(ONE_SECOND);
    p.try_wait().expect("failed to try_wait").expect("failed to get exit status");
}
#[test]
fn test_exit_with_code() {
    let mut p = Command::new(SHELL).spawn_pty().unwrap();
    let bytes = b"exit 42\r\n";
    p.write_all(bytes).expect("Failed to write to process");
    let exit_status = p.try_wait_timeout(ONE_SECOND).expect("Process wait failed").expect("Process did not exit");
    assert_eq!(exit_status.code().unwrap(), 42);
}
