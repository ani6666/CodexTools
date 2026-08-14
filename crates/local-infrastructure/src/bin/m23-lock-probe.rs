use std::{io, path::PathBuf, thread, time::Duration};

use codex_adapter as _;
use codex_domain::UnixMillis;
use local_infrastructure::CrossProcessWriteLock;
use rusqlite as _;
use windows_platform as _;
use zeroize as _;

fn main() {
    let mut arguments = std::env::args_os().skip(1);
    let root = PathBuf::from(arguments.next().expect("root"));
    let hold = arguments.next().unwrap_or_default();
    match CrossProcessWriteLock::try_acquire(&root, UnixMillis::new(1).expect("time")) {
        Ok(_lock) => {
            println!("LOCK_ACQUIRED");
            if hold == "stdin" {
                let mut release = String::new();
                io::stdin().read_line(&mut release).expect("release signal");
            } else {
                let milliseconds = hold.to_string_lossy().parse::<u64>().unwrap_or(0);
                thread::sleep(Duration::from_millis(milliseconds));
            }
        }
        Err(codex_application::SwitchExecutionError::Busy) => {
            println!("LOCK_CONTENDED");
            std::process::exit(2);
        }
        Err(_) => {
            println!("LOCK_ERROR");
            std::process::exit(3);
        }
    }
}
