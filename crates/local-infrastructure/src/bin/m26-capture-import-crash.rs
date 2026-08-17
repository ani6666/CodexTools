#![forbid(unsafe_code)]
#![allow(unused_crate_dependencies)]

use std::{
    io::{self, Write},
    path::PathBuf,
    thread,
    time::Duration,
};

use codex_adapter::{ControlledCodexAdapter, hash_bytes};
use codex_application::{
    CaptureImportRequest, CaptureImportStatus, ControlledCodexSource, ControlledRoot,
    ControlledRootResolver, ControlledScanStatus, ControlledSourceError,
    CredentialReferenceRepository,
};
use codex_domain::{
    CredentialRefId, EntityName, IdentityId, ManagedConfigPatchId, ModelPresetId, UnixMillis,
};
use local_infrastructure::{
    CaptureImportFaultPoint, CaptureImportFaults, CaptureImportService, CredentialService,
    CredentialServiceError, SqliteMetadataRepository, WindowsControlledRootReader,
};
use windows_platform::WindowsDpapiCredentialStore;
use zeroize::Zeroize;

#[derive(Clone)]
struct SyntheticResolver(PathBuf);

impl ControlledRootResolver for SyntheticResolver {
    fn resolve(&self, _root: ControlledRoot) -> Result<PathBuf, ControlledSourceError> {
        Ok(self.0.clone())
    }
}

struct BlockingFault(CaptureImportFaultPoint);

impl CaptureImportFaults for BlockingFault {
    fn interrupt(&mut self, point: CaptureImportFaultPoint) -> bool {
        if point != self.0 {
            return false;
        }
        println!("READY point={point:?}");
        io::stdout().flush().expect("flush READY");
        loop {
            thread::sleep(Duration::from_secs(60));
        }
    }
}

fn request(
    source: &impl ControlledCodexSource,
    offset: u8,
) -> Result<CaptureImportRequest, &'static str> {
    request_with_credential_offset(source, offset, offset)
}

fn request_with_credential_offset(
    source: &impl ControlledCodexSource,
    offset: u8,
    credential_offset: u8,
) -> Result<CaptureImportRequest, &'static str> {
    let ControlledScanStatus::Ready(summary) = source.scan(ControlledRoot::DefaultCodex) else {
        return Err("synthetic root did not scan");
    };
    let id = |prefix: u8| format!("{prefix:02x}{offset:02x}0000-0000-4000-8000-000000000001");
    Ok(CaptureImportRequest {
        root: ControlledRoot::DefaultCodex,
        scan_id: summary.scan_id,
        credential_id: CredentialRefId::parse(&format!(
            "11{credential_offset:02x}0000-0000-4000-8000-000000000001"
        ))
        .map_err(|_| "credential id")?,
        identity_id: IdentityId::parse(&id(0x22)).map_err(|_| "identity id")?,
        identity_name: EntityName::parse("隔离身份").map_err(|_| "identity name")?,
        preset_id: ModelPresetId::parse(&id(0x33)).map_err(|_| "preset id")?,
        preset_name: EntityName::parse("隔离模型").map_err(|_| "preset name")?,
        patch_id: ManagedConfigPatchId::parse(&id(0x44)).map_err(|_| "patch id")?,
        now: UnixMillis::new(1_000 + i64::from(offset)).map_err(|_| "time")?,
    })
}

fn point(value: &str) -> Option<CaptureImportFaultPoint> {
    match value {
        "after-journal" => Some(CaptureImportFaultPoint::AfterJournalPrepared),
        "after-credential" => Some(CaptureImportFaultPoint::AfterCredentialReady),
        "before-bundle" => Some(CaptureImportFaultPoint::BeforeBundleCommit),
        "after-bundle" => Some(CaptureImportFaultPoint::AfterBundleCommitted),
        "before-cleanup" => Some(CaptureImportFaultPoint::BeforeJournalCleanup),
        _ => None,
    }
}

fn run_crash(arguments: &[String]) -> i32 {
    if arguments.len() != 6 {
        return 64;
    }
    let controlled_root = PathBuf::from(&arguments[1]);
    let database = PathBuf::from(&arguments[2]);
    let credential_root = PathBuf::from(&arguments[3]);
    let Some(point) = point(&arguments[4]) else {
        return 64;
    };
    let Ok(offset) = arguments[5].parse::<u8>() else {
        return 64;
    };
    let source = ControlledCodexAdapter::new(WindowsControlledRootReader::new(SyntheticResolver(
        controlled_root,
    )));
    let Ok(request) = request(&source, offset) else {
        return 65;
    };
    let mut repository = match SqliteMetadataRepository::open(database) {
        Ok(repository) => repository,
        Err(_) => return 66,
    };
    let mut store = match WindowsDpapiCredentialStore::new(credential_root) {
        Ok(store) => store,
        Err(_) => return 67,
    };
    let status = CaptureImportService::new().capture_import_with_faults(
        &source,
        &mut repository,
        &mut store,
        request,
        &mut BlockingFault(point),
    );
    eprintln!("helper completed before crash boundary: {status:?}");
    70
}

fn synthetic_secret() -> Vec<u8> {
    let mut value = Vec::from(&b"sk-"[..]);
    value.extend((0..40).map(|index| b'A' + (index % 26)));
    value.push(b'Z');
    value
}

fn run_contender(arguments: &[String]) -> i32 {
    if arguments.len() != 5 {
        return 64;
    }
    let database = PathBuf::from(&arguments[1]);
    let credential_root = PathBuf::from(&arguments[2]);
    let Ok(id) = CredentialRefId::parse(&arguments[3]) else {
        return 64;
    };
    let mut repository = match SqliteMetadataRepository::open(database) {
        Ok(repository) => repository,
        Err(_) => return 66,
    };
    let mut store = match WindowsDpapiCredentialStore::new(credential_root) {
        Ok(store) => store,
        Err(_) => return 67,
    };
    let mut secret = synthetic_secret();
    let result = match arguments[4].as_str() {
        "create" => CredentialService::new(&mut repository, &mut store)
            .create_api_key(id.clone(), &mut secret, UnixMillis::new(4).expect("time"))
            .map(|_| ()),
        "rotate" => CredentialService::new(&mut repository, &mut store)
            .rotate_credential(
                &id,
                codex_domain::EntityVersion::initial(),
                &mut secret,
                UnixMillis::new(4).expect("time"),
            )
            .map(|_| ()),
        "delete" => CredentialService::new(&mut repository, &mut store)
            .delete_credential(&id, codex_domain::EntityVersion::initial()),
        _ => return 64,
    };
    secret.zeroize();
    match result {
        Err(CredentialServiceError::VersionConflict) => {
            println!("CONTENDER_VERSION_CONFLICT");
            2
        }
        Ok(()) => {
            let reference = repository.get_credential_reference(&id).ok().flatten();
            println!(
                "CONTENDER_UNEXPECTED_SUCCESS fingerprint={}",
                reference
                    .as_ref()
                    .map_or("none", |value| &value.credential_fingerprint().as_str()
                        [..8])
            );
            3
        }
        Err(error) => {
            println!("CONTENDER_OTHER {error:?}");
            4
        }
    }
}

fn run_import(arguments: &[String]) -> i32 {
    if arguments.len() != 5 {
        return 64;
    }
    let controlled_root = PathBuf::from(&arguments[1]);
    let database = PathBuf::from(&arguments[2]);
    let credential_root = PathBuf::from(&arguments[3]);
    let Ok(offset) = arguments[4].parse::<u8>() else {
        return 64;
    };
    let source = ControlledCodexAdapter::new(WindowsControlledRootReader::new(SyntheticResolver(
        controlled_root,
    )));
    let Ok(request) = request(&source, offset) else {
        return 65;
    };
    println!("IMPORT_READY");
    io::stdout().flush().expect("flush import ready");
    let mut release = String::new();
    io::stdin()
        .read_line(&mut release)
        .expect("import release signal");
    let mut repository = match SqliteMetadataRepository::open(database) {
        Ok(repository) => repository,
        Err(_) => return 66,
    };
    let mut store = match WindowsDpapiCredentialStore::new(credential_root) {
        Ok(store) => store,
        Err(_) => return 67,
    };
    match CaptureImportService::new().capture_import(&source, &mut repository, &mut store, request)
    {
        CaptureImportStatus::Imported(_) => {
            println!("IMPORT_IMPORTED");
            0
        }
        CaptureImportStatus::AlreadyImported(_) => {
            println!("IMPORT_ALREADY_IMPORTED");
            0
        }
        CaptureImportStatus::Conflict => {
            println!("IMPORT_CONFLICT");
            2
        }
        CaptureImportStatus::RecoveryRequired(diagnostic) => {
            println!("IMPORT_RECOVERY_REQUIRED {diagnostic:?}");
            3
        }
        CaptureImportStatus::CompatibilityProtected(reason) => {
            println!("IMPORT_COMPATIBILITY_PROTECTED {reason:?}");
            4
        }
    }
}

fn run_import_shared_credential(arguments: &[String]) -> i32 {
    if arguments.len() != 6 {
        return 64;
    }
    let controlled_root = PathBuf::from(&arguments[1]);
    let database = PathBuf::from(&arguments[2]);
    let credential_root = PathBuf::from(&arguments[3]);
    let Ok(offset) = arguments[4].parse::<u8>() else {
        return 64;
    };
    let Ok(credential_offset) = arguments[5].parse::<u8>() else {
        return 64;
    };
    let source = ControlledCodexAdapter::new(WindowsControlledRootReader::new(SyntheticResolver(
        controlled_root,
    )));
    let Ok(request) = request_with_credential_offset(&source, offset, credential_offset) else {
        return 65;
    };
    let mut repository = match SqliteMetadataRepository::open(database) {
        Ok(repository) => repository,
        Err(_) => return 66,
    };
    let mut store = match WindowsDpapiCredentialStore::new(credential_root) {
        Ok(store) => store,
        Err(_) => return 67,
    };
    println!("OWNER_CAS_READY");
    io::stdout().flush().expect("flush owner/CAS ready");
    let mut release = String::new();
    io::stdin()
        .read_line(&mut release)
        .expect("owner/CAS release signal");
    match CaptureImportService::new().capture_import(&source, &mut repository, &mut store, request)
    {
        CaptureImportStatus::Imported(_) => {
            println!("IMPORT_IMPORTED");
            0
        }
        CaptureImportStatus::AlreadyImported(_) => {
            println!("IMPORT_ALREADY_IMPORTED");
            0
        }
        CaptureImportStatus::Conflict => {
            println!("IMPORT_CONFLICT");
            2
        }
        CaptureImportStatus::RecoveryRequired(diagnostic) => {
            println!("IMPORT_RECOVERY_REQUIRED {diagnostic:?}");
            3
        }
        CaptureImportStatus::CompatibilityProtected(reason) => {
            println!("IMPORT_COMPATIBILITY_PROTECTED {reason:?}");
            4
        }
    }
}

fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let code = match arguments.first().map(String::as_str) {
        Some("crash") => run_crash(&arguments),
        Some("contend") => run_contender(&arguments),
        Some("import") => run_import(&arguments),
        Some("import-shared-credential") => run_import_shared_credential(&arguments),
        _ => 64,
    };
    let _ = hash_bytes(b"synthetic helper linkage");
    std::process::exit(code);
}
