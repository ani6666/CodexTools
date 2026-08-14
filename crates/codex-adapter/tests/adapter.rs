use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use codex_adapter::CodexAdapter;
use codex_application::{
    CompatibilityReason, DesiredManagedConfig, FormatGeneration, LineEnding, ScanStatus,
};
use codex_domain::{
    CredentialBackend, CredentialKind, CredentialRefId, CredentialReference, EndpointUrl,
    EntityName, ModelId, ProviderId, UnixMillis,
};

struct TempHome(PathBuf);
impl TempHome {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "codextools-m22-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> &Path {
        &self.0
    }
    fn write(&self, config: &[u8], auth: &[u8]) {
        fs::write(self.0.join("config.toml"), config).unwrap();
        fs::write(self.0.join("auth.json"), auth).unwrap();
    }
}
impl Drop for TempHome {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn fixture(name: &str, file: &str) -> Vec<u8> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
        .join(file)
        .pipe(fs::read)
        .unwrap()
}
trait Pipe: Sized {
    fn pipe<T>(self, f: impl FnOnce(Self) -> T) -> T {
        f(self)
    }
}
impl<T> Pipe for T {}

fn ready(status: ScanStatus) -> codex_application::ActualCodexState {
    match status {
        ScanStatus::Ready(v) => *v,
        other => panic!("expected ready, got {other:?}"),
    }
}

#[test]
fn scans_all_fixed_profiles_from_explicit_temporary_roots() {
    let adapter = CodexAdapter::new();
    for (name, generation, bom, newline) in [
        (
            "g1-api-key",
            FormatGeneration::ApiKeyBaseline,
            false,
            LineEnding::Lf,
        ),
        (
            "g2-oauth",
            FormatGeneration::SyntheticOAuth,
            false,
            LineEnding::CrLf,
        ),
        (
            "g3-current-shape",
            FormatGeneration::CurrentShape,
            true,
            LineEnding::Lf,
        ),
    ] {
        let home = TempHome::new(name);
        home.write(&fixture(name, "config.toml"), &fixture(name, "auth.json"));
        let state = ready(adapter.scan_explicit_root(home.path()));
        assert_eq!(state.config.generation, generation);
        assert_eq!(state.config.has_bom, bom);
        assert_eq!(state.config.line_ending, newline);
        assert_eq!(state.config.provider_id.as_str(), "sample");
    }
}

#[test]
fn planning_is_deterministic_and_preserves_unknown_bytes() {
    let adapter = CodexAdapter::new();
    let home = TempHome::new("plan");
    let config = fixture("g2-oauth", "config.toml");
    home.write(&config, &fixture("g2-oauth", "auth.json"));
    let actual = ready(adapter.scan_explicit_root(home.path()));
    let credential = CredentialReference::new(
        CredentialRefId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
        CredentialKind::OAuthBundle,
        CredentialBackend::WindowsDpapiCurrentUser,
        actual.authentication.schema_fingerprint.clone(),
        actual.authentication.credential_fingerprint.clone(),
        UnixMillis::new(1).unwrap(),
    );
    let desired = DesiredManagedConfig {
        provider_id: ProviderId::parse("sample").unwrap(),
        provider_display_name: EntityName::parse("Target Provider").unwrap(),
        api_base_url: EndpointUrl::parse("https://TARGET/v2").unwrap(),
        model_id: ModelId::parse("gpt-TARGET-2").unwrap(),
    };
    let first = adapter.plan_config(&actual, &desired, &credential).unwrap();
    let second = adapter.plan_config(&actual, &desired, &credential).unwrap();
    assert_eq!(first.target_bytes, second.target_bytes);
    assert_eq!(first.target_sha256, second.target_sha256);
    assert_eq!(first.baseline_sha256, actual.config.baseline_sha256);
    let mut expected = String::from_utf8(config).unwrap();
    expected = expected
        .replacen("model = \"gpt-SAMPLE-2\"", "model = \"gpt-TARGET-2\"", 1)
        .replacen(
            "name = \"Sample Provider\"",
            "name = \"Target Provider\"",
            1,
        )
        .replacen(
            "base_url = \"https://HOST/v1\"",
            "base_url = \"https://TARGET/v2\"",
            1,
        );
    assert_eq!(first.target_bytes.as_slice(), expected.as_bytes());
    assert!(expected.contains("unknown_future_key = \"KEEP_ME\""));
    assert!(expected.contains("unknown_provider_option = true"));
    assert!(expected.contains("# 保留行尾注释"));
    assert!(expected.contains("\r\n"));
    let diff = format!("{:?}", first.diff);
    assert!(!diff.contains(credential.credential_fingerprint().as_str()));
    assert!(!diff.contains("access_token"));
    assert!(diff.contains("[REDACTED]"));
}

#[test]
fn compatibility_matrix_fails_closed_for_m1_boundaries() {
    let adapter = CodexAdapter::new();
    let auth = br#"{"OPENAI_API_KEY":"API_KEY_SAMPLE"}"#;
    let base = "# sample\nmodel = \"gpt-SAMPLE\"\nmodel_provider = \"sample\"\n[model_providers.sample]\nname = \"Sample Provider\"\nbase_url = \"https://HOST/v1\"\nenv_key = \"API_KEY_ENV\"\n";
    let cases: Vec<Vec<u8>> = vec![
        vec![0xff, 0xfe],
        base.replace("\nmodel_provider", "\r\nmodel_provider")
            .into_bytes(),
        base.replace("# sample\n", "# sample\r").into_bytes(),
        format!("{base}x = [1]\n").into_bytes(),
        format!("{base}x = {{ a = 1 }}\n").into_bytes(),
        format!("{base}[[x]]\n").into_bytes(),
        format!("{base}[\"x\"]\n").into_bytes(),
        format!("{base}\"x\" = 1\n").into_bytes(),
        format!("{base}x = \"\"\"a\"\"\"\n").into_bytes(),
        format!("{base}x = 'a'\n").into_bytes(),
        format!("{base}x = 1.5\n").into_bytes(),
        format!("{base}x = 1e2\n").into_bytes(),
        format!("{base}x = 2026-01-01\n").into_bytes(),
        format!("{base}x = 0x10\n").into_bytes(),
        format!("{base}x = 999999999999999999999999\n").into_bytes(),
        format!("model = \"again\"\n{base}").into_bytes(),
        format!("model_provider = \"again\"\n{base}").into_bytes(),
        format!("{base}[model_providers.sample]\n").into_bytes(),
        b"x=1\n[x]\n".to_vec(),
        b"[x]\ny=1\nx=2\n[x.z]\n".to_vec(),
        format!("model_providers = \"x\"\n{base}").into_bytes(),
        format!("{base}[model_providers.sample.extra]\nx=1\n").into_bytes(),
        format!("{base}[x\n").into_bytes(),
        format!("{base}nonsense\n").into_bytes(),
        format!("{base}= 1\n").into_bytes(),
        format!("{base}x.y = 1\n").into_bytes(),
        format!("{base}键 = 1\n").into_bytes(),
        format!("{base}x = \"bad\\q\"\n").into_bytes(),
        format!("{base}x = \"ok\" trailing\n").into_bytes(),
        [base.as_bytes(), b"x = \"a\x01\"\n"].concat(),
        base.replace("model = \"gpt-SAMPLE\"\n", "").into_bytes(),
        base.replace("model_provider = \"sample\"\n", "")
            .into_bytes(),
        base.replace("name = \"Sample Provider\"\n", "")
            .into_bytes(),
        base.replace("base_url = \"https://HOST/v1\"\n", "")
            .into_bytes(),
    ];
    assert_eq!(cases.len(), 34);
    for (index, config) in cases.into_iter().enumerate() {
        let home = TempHome::new(&format!("case-{index}"));
        home.write(&config, auth);
        assert!(
            matches!(
                adapter.scan_explicit_root(home.path()),
                ScanStatus::CompatibilityProtected(_)
            ),
            "case {index} was accepted"
        );
    }
}

#[test]
fn missing_unknown_auth_and_secret_in_unknown_config_are_protected() {
    let adapter = CodexAdapter::new();
    let home = TempHome::new("missing");
    assert_eq!(
        adapter.scan_explicit_root(home.path()),
        ScanStatus::CompatibilityProtected(CompatibilityReason::MissingConfig)
    );
    fs::write(
        home.path().join("config.toml"),
        fixture("g1-api-key", "config.toml"),
    )
    .unwrap();
    assert_eq!(
        adapter.scan_explicit_root(home.path()),
        ScanStatus::CompatibilityProtected(CompatibilityReason::MissingAuthentication)
    );
    fs::write(home.path().join("auth.json"), b"{}").unwrap();
    assert_eq!(
        adapter.scan_explicit_root(home.path()),
        ScanStatus::CompatibilityProtected(CompatibilityReason::UnknownAuthenticationShape)
    );
    let marker = format!("{}{}", "sk-", "A".repeat(24));
    let config = String::from_utf8(fixture("g1-api-key", "config.toml")).unwrap()
        + &format!("unknown = \"prefix-{marker}\"\n");
    home.write(config.as_bytes(), br#"{"OPENAI_API_KEY":"API_KEY_SAMPLE"}"#);
    let result = adapter.scan_explicit_root(home.path());
    assert!(matches!(result, ScanStatus::CompatibilityProtected(_)));
    assert!(!format!("{result:?}").contains(&marker));
}

#[test]
fn auth_json_strictly_rejects_invalid_grammar_without_echoing_input() {
    let adapter = CodexAdapter::new();
    let config = fixture("g1-api-key", "config.toml");
    let invalid = vec![
        br#"{"OPENAI_API_KEY":"TOKEN","x":1.2.3}"#.to_vec(),
        br#"{"OPENAI_API_KEY":"TOKEN","x":01}"#.to_vec(),
        br#"{"OPENAI_API_KEY":"TOKEN","x":1.}"#.to_vec(),
        br#"{"OPENAI_API_KEY":"TOKEN","x":1e}"#.to_vec(),
        br#"{"OPENAI_API_KEY":"TOKEN","x":"\uZZZZ"}"#.to_vec(),
        br#"{"OPENAI_API_KEY":"TOKEN","x":"\uD800"}"#.to_vec(),
        [
            br#"{"OPENAI_API_KEY":"TOKEN","x":""#.as_slice(),
            &[0xff],
            br#""}"#.as_slice(),
        ]
        .concat(),
        [
            br#"{"OPENAI_API_KEY":"TOKEN","x":1,"#.as_slice(),
            &[0x0b],
            br#""y":2}"#.as_slice(),
        ]
        .concat(),
    ];
    for (index, auth) in invalid.into_iter().enumerate() {
        let home = TempHome::new(&format!("strict-auth-invalid-{index}"));
        home.write(&config, &auth);
        let result = adapter.scan_explicit_root(home.path());
        assert_eq!(
            result,
            ScanStatus::CompatibilityProtected(CompatibilityReason::UnknownAuthenticationShape),
            "invalid auth case {index} was accepted"
        );
        assert!(!format!("{result:?}").contains("TOKEN"));
    }
}

#[test]
fn auth_json_accepts_valid_utf8_numbers_and_escapes() {
    let adapter = CodexAdapter::new();
    let config = fixture("g1-api-key", "config.toml");
    let valid = [
        br#"{"OPENAI_API_KEY":"TOKEN","x":-0.25e+2}"#.as_slice(),
        r#"{"OPENAI_API_KEY":"TOKEN","x":"你好"}"#.as_bytes(),
        br#"{"OPENAI_API_KEY":"TOKEN","x":"\u4F60\u597D"}"#.as_slice(),
        br#"{"OPENAI_API_KEY":"TOKEN","x":"\uD83D\uDE00"}"#.as_slice(),
        br#"{"OPENAI_API_KEY":"TOKEN","x":[0,1,-2,3.5,6e7]}"#.as_slice(),
    ];
    for (index, auth) in valid.into_iter().enumerate() {
        let home = TempHome::new(&format!("strict-auth-valid-{index}"));
        home.write(&config, auth);
        assert!(
            matches!(
                adapter.scan_explicit_root(home.path()),
                ScanStatus::Ready(_)
            ),
            "valid auth case {index} was rejected"
        );
    }
}

#[test]
fn auth_json_rejects_unicode_escape_equivalent_duplicate_keys() {
    let adapter = CodexAdapter::new();
    let config = fixture("g1-api-key", "config.toml");
    let duplicates = [
        br#"{"OPENAI_API_KEY":"TOKEN","\u004fPENAI_API_KEY":"TOKEN"}"#.as_slice(),
        br#"{"\u004fPENAI_API_KEY":"TOKEN","OPENAI_API_KEY":"TOKEN"}"#.as_slice(),
        br#"{"tokens":{"id_token":"ID","\u0069d_token":"ID","access_token":"ACCESS","refresh_token":"REFRESH","account_id":"ACCOUNT"}}"#.as_slice(),
        br#"{"tokens":{"id_token":"ID","access_token":"ACCESS","refresh_token":"REFRESH","account_id":"ACCOUNT"},"\u0074okens":{"id_token":"ID","access_token":"ACCESS","refresh_token":"REFRESH","account_id":"ACCOUNT"}}"#.as_slice(),
    ];
    for (index, auth) in duplicates.into_iter().enumerate() {
        let home = TempHome::new(&format!("unicode-equivalent-duplicate-{index}"));
        home.write(&config, auth);
        assert!(matches!(
            adapter.scan_explicit_root(home.path()),
            ScanStatus::CompatibilityProtected(CompatibilityReason::UnknownAuthenticationShape)
        ));
    }
}

#[test]
fn private_key_headers_in_unknown_config_are_compatibility_protected() {
    let adapter = CodexAdapter::new();
    let auth = br#"{"OPENAI_API_KEY":"TOKEN"}"#;
    for label in ["", "RSA ", "OPENSSH ", "EC ", "DSA "] {
        let marker = format!("{}{}{}", "-----BEGIN ", label, "PRIVATE KEY-----");
        let config = String::from_utf8(fixture("g1-api-key", "config.toml")).unwrap()
            + &format!("unknown = \"prefix-{marker}\"\n");
        let home = TempHome::new("private-key-header");
        home.write(config.as_bytes(), auth);
        let result = adapter.scan_explicit_root(home.path());
        assert!(matches!(
            result,
            ScanStatus::CompatibilityProtected(CompatibilityReason::UnsupportedTomlSubset)
        ));
        assert!(!format!("{result:?}").contains(&marker));
    }
}

#[test]
fn cross_provider_planning_requires_predeclared_table_and_preserves_both_tables() {
    let adapter = CodexAdapter::new();
    let auth = br#"{"OPENAI_API_KEY":"TOKEN"}"#;
    let only_a = b"model = \"model-a\"\nmodel_provider = \"a\"\n[model_providers.a]\nname = \"Provider A\"\nbase_url = \"https://HOST/a\"\nunknown_a = \"KEEP_A\"\n";
    let home = TempHome::new("provider-missing");
    home.write(only_a, auth);
    let actual = ready(adapter.scan_explicit_root(home.path()));
    let credential = CredentialReference::new(
        CredentialRefId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
        CredentialKind::ApiKey,
        CredentialBackend::WindowsDpapiCurrentUser,
        actual.authentication.schema_fingerprint.clone(),
        actual.authentication.credential_fingerprint.clone(),
        UnixMillis::new(1).unwrap(),
    );
    let desired_b = DesiredManagedConfig {
        provider_id: ProviderId::parse("b").unwrap(),
        provider_display_name: EntityName::parse("Provider B Target").unwrap(),
        api_base_url: EndpointUrl::parse("https://HOST/b-target").unwrap(),
        model_id: ModelId::parse("model-b-target").unwrap(),
    };
    assert_eq!(
        adapter.plan_config(&actual, &desired_b, &credential),
        Err(CompatibilityReason::MissingManagedField)
    );

    let both = b"model = \"model-a\"\nmodel_provider = \"a\"\n[model_providers.a]\nname = \"Provider A\"\nbase_url = \"https://HOST/a\"\nunknown_a = \"KEEP_A\"\n[model_providers.b]\nname = \"Provider B\"\nbase_url = \"https://HOST/b\"\nunknown_b = \"KEEP_B\"\n";
    let roundtrip = TempHome::new("provider-roundtrip");
    roundtrip.write(both, auth);
    let state_a = ready(adapter.scan_explicit_root(roundtrip.path()));
    let plan_b = adapter
        .plan_config(&state_a, &desired_b, &credential)
        .unwrap();
    let target_b = String::from_utf8(plan_b.target_bytes.to_vec()).unwrap();
    assert!(target_b.contains("unknown_a = \"KEEP_A\""));
    assert!(target_b.contains("unknown_b = \"KEEP_B\""));
    roundtrip.write(&plan_b.target_bytes, auth);
    let state_b = ready(adapter.scan_explicit_root(roundtrip.path()));
    let desired_a = DesiredManagedConfig {
        provider_id: ProviderId::parse("a").unwrap(),
        provider_display_name: EntityName::parse("Provider A").unwrap(),
        api_base_url: EndpointUrl::parse("https://HOST/a").unwrap(),
        model_id: ModelId::parse("model-a").unwrap(),
    };
    let plan_a = adapter
        .plan_config(&state_b, &desired_a, &credential)
        .unwrap();
    let target_a = String::from_utf8(plan_a.target_bytes.to_vec()).unwrap();
    assert!(target_a.contains("unknown_a = \"KEEP_A\""));
    assert!(target_a.contains("unknown_b = \"KEEP_B\""));
    assert!(target_a.contains("model_provider = \"a\""));
    assert!(target_a.contains("model = \"model-a\""));
}

#[test]
fn scanned_config_debug_never_formats_owned_config_bytes() {
    let adapter = CodexAdapter::new();
    let canary = "CONFIG_CANARY_VALUE_ABC123";
    let config = format!(
        "model = \"gpt-SAMPLE\"\n\
         model_provider = \"sample\"\n\
         [model_providers.sample]\n\
         name = \"Sample Provider\"\n\
         base_url = \"https://HOST/v1\"\n\
         unknown_future_key = \"{canary}\"\n"
    );
    let actual = ready(adapter.scan_memory(config.as_bytes(), br#"{"OPENAI_API_KEY":"TOKEN"}"#));

    let debug = format!("{actual:?}");
    assert!(!debug.contains(canary));
    assert!(!debug.contains("original_bytes"));
    assert!(!debug.contains(&format!("{:?}", config.as_bytes())));
    assert!(debug.contains("[REDACTED_CONFIG_BYTES]"));
}

#[test]
fn scanned_config_unwind_exposes_only_a_synthetic_panic_payload() {
    let adapter = CodexAdapter::new();
    let canary = "CONFIG_UNWIND_CANARY_456XYZ";
    let config = format!(
        "model = \"gpt-SAMPLE\"\n\
         model_provider = \"sample\"\n\
         [model_providers.sample]\n\
         name = \"Sample Provider\"\n\
         base_url = \"https://HOST/v1\"\n\
         unknown_future_key = \"{canary}\"\n"
    );
    let panic = std::panic::catch_unwind(|| {
        let actual =
            ready(adapter.scan_memory(config.as_bytes(), br#"{"OPENAI_API_KEY":"TOKEN"}"#));
        assert!(!format!("{actual:?}").contains(canary));
        panic!("synthetic config unwind");
    });

    let payload = panic.unwrap_err();
    let payload = payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or_default();
    assert_eq!(payload, "synthetic config unwind");
    assert!(!payload.contains(canary));
}
use zeroize as _;
