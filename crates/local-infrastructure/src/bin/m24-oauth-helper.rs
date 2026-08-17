#![forbid(unsafe_code)]

use codex_adapter as _;
use codex_application as _;
use codex_domain as _;
use local_infrastructure as _;
use native_tls as _;
use rusqlite as _;
use std::{env, fs, path::PathBuf, process::Command, thread, time::Duration};
use zeroize as _;

fn main() {
    let mut arguments = env::args_os().skip(1);
    let mode = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .unwrap_or_default();
    let capture = arguments.next().map(PathBuf::from).unwrap_or_default();
    let audit = arguments.next().map(PathBuf::from).unwrap_or_default();
    match mode.as_str() {
        "success" => {
            fs::write(capture.join("auth.json"), oauth_material()).unwrap();
        }
        "cancel" => std::process::exit(2),
        "timeout" => thread::sleep(Duration::from_secs(2)),
        "abnormal" => std::process::exit(7),
        "no_auth" => {}
        "unknown" => fs::write(capture.join("auth.json"), b"{\"mystery\":\"TOKEN\"}\n").unwrap(),
        "outside" => {
            fs::write(audit.join("outside-write.txt"), b"NON_SECRET_MARKER").unwrap();
            fs::write(capture.join("auth.json"), oauth_material()).unwrap();
        }
        "outside-directory" => {
            fs::create_dir(audit.join("outside-directory")).unwrap();
            fs::write(capture.join("auth.json"), oauth_material()).unwrap();
        }
        "env-clear" => {
            let forbidden = env::vars_os().any(|(key, _)| {
                let key = key.to_string_lossy().to_ascii_uppercase();
                key != "CODEX_HOME"
                    && (key.contains("TOKEN")
                        || key.contains("API_KEY")
                        || key.contains("PASSWORD")
                        || key.contains("SECRET")
                        || key == "PATH")
            });
            if forbidden || env::var_os("CODEX_HOME").as_deref() != Some(capture.as_os_str()) {
                std::process::exit(8);
            }
            fs::write(capture.join("auth.json"), oauth_material()).unwrap();
        }
        "descendant-success" => {
            spawn_descendant(&capture, &audit);
            fs::write(capture.join("auth.json"), oauth_material()).unwrap();
        }
        "descendant-timeout" => {
            spawn_descendant(&capture, &audit);
            thread::sleep(Duration::from_secs(2));
        }
        "descendant-cancel" => {
            spawn_descendant(&capture, &audit);
            std::process::exit(2);
        }
        "descendant-abnormal" => {
            spawn_descendant(&capture, &audit);
            std::process::exit(7);
        }
        "descendant-writer" => {
            thread::sleep(Duration::from_millis(350));
            fs::write(audit.join("descendant-late-write.txt"), b"LATE_WRITE").unwrap();
        }
        "auth-junction" => {
            let target = audit.join("junction-target");
            let command = env::var_os("ComSpec").unwrap_or_else(|| "cmd.exe".into());
            let status = Command::new(command)
                .args(["/d", "/c", "mklink", "/J"])
                .arg(capture.join("auth.json"))
                .arg(target)
                .status()
                .unwrap();
            if !status.success() {
                std::process::exit(8);
            }
        }
        "outside-reparse" => {
            let target = audit.join("reparse-target");
            let command = env::var_os("ComSpec").unwrap_or_else(|| "cmd.exe".into());
            let status = Command::new(command)
                .args(["/d", "/c", "mklink", "/J"])
                .arg(audit.join("outside-junction"))
                .arg(target)
                .status()
                .unwrap();
            if !status.success() {
                std::process::exit(8);
            }
            fs::write(capture.join("auth.json"), oauth_material()).unwrap();
        }
        "capture-root-junction" => {
            fs::remove_file(capture.join("config.toml")).unwrap();
            fs::remove_dir(&capture).unwrap();
            let target = audit.join("capture-root-target");
            let command = env::var_os("ComSpec").unwrap_or_else(|| "cmd.exe".into());
            let status = Command::new(command)
                .args(["/d", "/c", "mklink", "/J"])
                .arg(&capture)
                .arg(target)
                .status()
                .unwrap();
            if !status.success() {
                std::process::exit(8);
            }
        }
        _ => std::process::exit(9),
    }
}

fn spawn_descendant(capture: &PathBuf, audit: &PathBuf) {
    let child = Command::new(env::current_exe().unwrap())
        .arg("descendant-writer")
        .arg(capture)
        .arg(audit)
        .spawn()
        .unwrap();
    windows_platform::detach_std_child(child).unwrap();
}

fn oauth_material() -> Vec<u8> {
    let mut marker = String::from("sk-");
    marker.extend(std::iter::repeat_n('O', 40));
    format!(
        "{{\"tokens\":{{\"id_token\":\"{marker}\",\"access_token\":\"{marker}\",\"refresh_token\":\"{marker}\",\"account_id\":\"ACCOUNT\"}},\"last_refresh\":\"2026-01-01T00:00:00Z\"}}\r\n"
    )
    .into_bytes()
}
