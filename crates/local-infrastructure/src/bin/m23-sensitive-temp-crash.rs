use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use codex_adapter::{CodexAdapter, hash_bytes};
use codex_application::{
    Clock, FileBaseline, ScanStatus, StabilityWindow, SwitchExecutionError, SwitchPlan,
};
use codex_domain::{ModelId, ProviderId, SwitchTransactionId, UnixMillis};
use local_infrastructure::{
    FaultInjector, SensitiveTempIo, SqliteMetadataRepository, SwitchExecutor,
};
use rusqlite as _;
use windows_platform::{RootNamespacePin, SensitiveTempFile};
use zeroize::{Zeroize, Zeroizing};

struct FixedClock;
impl Clock for FixedClock {
    fn now(&self) -> UnixMillis {
        UnixMillis::new(150).expect("fixed time")
    }
}

struct NoWait;
impl StabilityWindow for NoWait {
    fn between_observations(&mut self, _: &Path) -> Result<(), SwitchExecutionError> {
        Ok(())
    }
}

struct NoFault;
impl FaultInjector for NoFault {
    fn check(
        &mut self,
        _: local_infrastructure::FaultPoint,
    ) -> Option<local_infrastructure::FaultDisposition> {
        None
    }
}

enum CrashMode {
    CreateReturn,
    ClearReturn,
    Partial(usize),
    RenameConfig,
}

struct CrashIo {
    mode: CrashMode,
    fired: bool,
}

impl CrashIo {
    fn ready(&mut self, label: &str, length: u64) -> ! {
        self.fired = true;
        println!("READY phase={label} length={length}");
        io::stdout().flush().expect("flush READY");
        loop {
            thread::sleep(Duration::from_secs(60));
        }
    }
}

impl SensitiveTempIo for CrashIo {
    fn create_delete_armed(
        &mut self,
        root: &RootNamespacePin,
        basename: &str,
    ) -> io::Result<SensitiveTempFile> {
        SensitiveTempFile::create_delete_armed_with_post_create(root, basename, || {
            if !self.fired
                && matches!(self.mode, CrashMode::CreateReturn)
                && basename.starts_with(".config.toml.")
            {
                self.ready("create-return", 0);
            }
            Ok(())
        })
    }

    fn clear_delete_on_close(
        &mut self,
        file: &mut SensitiveTempFile,
        root: &RootNamespacePin,
    ) -> io::Result<()> {
        file.clear_delete_on_close(root)?;
        if !self.fired
            && matches!(self.mode, CrashMode::ClearReturn)
            && file.basename().starts_with(".config.toml.")
        {
            self.ready("clear-return", file.length()?);
        }
        Ok(())
    }

    fn write(&mut self, file: &mut SensitiveTempFile, bytes: &[u8]) -> io::Result<usize> {
        if !self.fired && file.basename().starts_with(".auth.json.") {
            if let CrashMode::Partial(limit) = self.mode {
                let count = file.write_once(&bytes[..limit.min(bytes.len())])?;
                file.flush()?;
                file.sync_all()?;
                let length = file.length()?;
                if length != count as u64 {
                    return Err(io::Error::other("same-handle length mismatch"));
                }
                self.ready("partial-write", length);
            }
        }
        file.write_once(bytes)
    }

    fn rename_relative(
        &mut self,
        file: &mut SensitiveTempFile,
        root: &RootNamespacePin,
        publish_basename: &str,
    ) -> io::Result<()> {
        file.rename_relative(root, publish_basename)?;
        if !self.fired
            && matches!(self.mode, CrashMode::RenameConfig)
            && publish_basename == "config.toml"
        {
            self.ready("rename-succeeded", file.length()?);
        }
        Ok(())
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        std::process::exit(64);
    }
    let root = PathBuf::from(&args[1]);
    let db = PathBuf::from(&args[2]);
    let mode = match args[3].as_str() {
        "create-return" => CrashMode::CreateReturn,
        "clear-return" => CrashMode::ClearReturn,
        "partial" => CrashMode::Partial(args[4].parse().expect("partial byte count")),
        "rename" => CrashMode::RenameConfig,
        _ => std::process::exit(64),
    };
    let mut auth = Zeroizing::new(
        std::env::var("CODEXTOOLS_SYNTHETIC_AUTH")
            .expect("synthetic auth fixture")
            .into_bytes(),
    );
    let source_config = fs::read(root.join("config.toml")).expect("source config");
    let source_auth = fs::read(root.join("auth.json")).expect("source auth");
    let target_config = Zeroizing::new(
        String::from_utf8(source_config.clone())
            .expect("fixture UTF-8")
            .replace("gpt-SAMPLE-1", "gpt-TARGET-1")
            .replace("Sample Provider", "Target Provider")
            .replace("https://HOST/v1", "https://TARGET/v2")
            .into_bytes(),
    );
    let ScanStatus::Ready(target) = CodexAdapter::new().scan_memory(&target_config, &auth) else {
        std::process::exit(65);
    };
    let plan = SwitchPlan::new_zeroizing(
        SwitchTransactionId::parse("e1000000-0000-4000-8000-000000000001").expect("id"),
        fs::canonicalize(&root).expect("canonical root"),
        FileBaseline::present(source_config.len() as u64, hash_bytes(&source_config)),
        FileBaseline::present(source_auth.len() as u64, hash_bytes(&source_auth)),
        target_config,
        Zeroizing::new(std::mem::take(&mut *auth)),
        ProviderId::parse("sample").expect("provider"),
        ModelId::parse("gpt-TARGET-1").expect("model"),
        target.authentication.credential_fingerprint,
        UnixMillis::new(100).expect("created"),
        UnixMillis::new(200).expect("expires"),
    )
    .expect("plan");
    auth.zeroize();
    let mut repository = SqliteMetadataRepository::open(db).expect("repository");
    let mut wait = NoWait;
    let mut faults = NoFault;
    let result = SwitchExecutor::new_with_sensitive_temp_io(
        &mut repository,
        &FixedClock,
        &mut wait,
        &mut faults,
        CrashIo { mode, fired: false },
    )
    .execute(&plan);
    eprintln!("helper exited before READY: {result:?}");
    std::process::exit(70);
}
