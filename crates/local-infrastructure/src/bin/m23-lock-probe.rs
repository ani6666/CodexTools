use std::{path::PathBuf, thread, time::Duration};

use codex_adapter as _;
use codex_domain::UnixMillis;
use local_infrastructure::CrossProcessWriteLock;
use rusqlite as _;
use windows_platform as _;
use zeroize as _;

fn main() {
    let mut arguments = std::env::args_os().skip(1);
    let root = PathBuf::from(arguments.next().expect("root"));
    let hold = arguments
        .next()
        .and_then(|value| value.to_string_lossy().parse::<u64>().ok())
        .unwrap_or(0);
    match CrossProcessWriteLock::try_acquire(&root, UnixMillis::new(1).expect("time")) {
        Ok(_lock) => {
            println!("LOCK_ACQUIRED");
            thread::sleep(Duration::from_millis(hold));
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
