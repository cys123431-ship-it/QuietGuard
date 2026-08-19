use crate::rules::Rules;
use std::env;
use std::fs;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub fn run_extra_scan4() -> Vec<String> {
    let rules = Rules::load();
    let mut out = Vec::with_capacity(80);
    out.push("--- 시스템 위장/정책/확장 세부 점검 ---".into());
    scan_fake_system_processes(&mut out);
    scan_numeric_system_files(&mut out);
    scan_group_policy_registry(&mut out, &rules);
    scan_extension_metadata(&mut out);
    out
}

fn hidden_output(program: &str, args: &[&str]) -> String {
    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.creation_flags(CREATE_NO_WINDOW);
    match cmd.output() {
        Ok(o) => decode_output(&o.stdout),
        Err(_) => String::new(),
    }
}

fn decode_output(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xFF, 0xFE]) {
        let u16s: Vec<u16> = bytes[2..].chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        return String::from_utf16_lossy(&u16s);
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        let u16s: Vec<u16> = bytes[2..].chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
        return String::from_utf16_lossy(&u16s);
    }
    String::from_utf8_lossy(bytes).into_owned()
}

fn scan_fake_system_processes(out: &mut Vec<String>) {
    let script = r#"$names=@('svchost.exe','lsass.exe','csrss.exe','winlogon.exe','services.exe','smss.exe','wininit.exe','spoolsv.exe','taskhostw.exe','dllhost.exe','conhost.exe'); Get-CimInstance Win32_Process | Where-Object { $names -contains $_.Name } | ForEach-Object { Write-Output ($_.Name + '|' + $_.ExecutablePath) }"#;
    let text = hidden_output("powershell.exe", &[
        "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script,
    ]);
    if text.is_empty() {
        out.push("[정보] 핵심 시스템 프로세스 경로를 조회하지 못했습니다.".into());
        return;
    }

    let windir = env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into()).to_ascii_lowercase();
    let system32 = format!("{}\\system32\\", windir.trim_end_matches('\\'));
    let syswow64 = format!("{}\\syswow64\\", windir.trim_end_matches('\\'));
    let mut checked = 0usize;
    let mut suspicious = 0usize;

    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let Some((name, path)) = line.split_once('|') else { continue; };
        let path = path.trim();
        if path.is_empty() { continue; }
        checked += 1;
        let lower = path.to_ascii_lowercase();
        let expected = lower.starts_with(&system32) || lower.starts_with(&syswow64);
        if !expected {
            suspicious += 1;
            out.push(format!("[주의] 시스템 이름 프로세스가 Windows 시스템 폴더 밖에서 실행: {} -> {}", name, compact(path, 130)));
        }
    }
    out.push(format!("[정보] 핵심 시스템 이름 프로세스 {}개 경로 확인, 주의 {}개", checked, suspicious));
}

fn scan_numeric_system_files(out: &mut Vec<String>) {
    let windir = env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into());
    let roots = [
        ("System32", PathBuf::from(&windir).join("System32")),
        ("SysWOW64", PathBuf::from(&windir).join("SysWOW64")),
    ];
    let mut matches = 0usize;
    for (label, root) in roots {
        let Ok(items) = fs::read_dir(root) else { continue; };
        for entry in items.flatten() {
            let path = entry.path();
            let Ok(meta) = entry.metadata() else { continue; };
            if !meta.is_file() || !is_exec_like(&path) { continue; }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else { continue; };
            if (stem.len() == 4 || stem.len() == 12) && stem.chars().all(|c| c.is_ascii_digit()) {
                matches += 1;
                if matches <= 30 {
                    out.push(format!("[확인] {} 숫자형 실행 가능 파일: {}", label, path.display()));
                }
            }
        }
    }
    out.push(format!("[정보] System32/SysWOW64 숫자형(4/12자리) 실행 가능 파일 {}개", matches));
}

fn scan_group_policy_registry(out: &mut Vec<String>, rules: &Rules) {
    let windir = env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into());
    let base = PathBuf::from(&windir).join("System32");
    let mut files = vec![
        base.join("GroupPolicy\\Machine\\Registry.pol"),
        base.join("GroupPolicy\\User\\Registry.pol"),
    ];

    let users = base.join("GroupPolicyUsers");
    if let Ok(items) = fs::read_dir(users) {
        for item in items.flatten() {
            files.push(item.path().join("User\\Registry.pol"));
        }
    }

    let mut existing = 0usize;
    let mut suspicious_files = 0usize;
    for path in files {
        let Ok(bytes) = fs::read(&path) else { continue; };
        existing += 1;
        let text = decode_registry_pol(&bytes).to_ascii_lowercase();
        let mut hits = Vec::new();
        for token in rules.suspicious_commands.iter().chain(rules.suspicious_paths.iter()) {
            if text.contains(token) && !hits.iter().any(|x: &&String| x.eq_ignore_ascii_case(token)) {
                hits.push(token);
            }
        }
        if !hits.is_empty() {
            suspicious_files += 1;
            let labels = hits.iter().take(5).map(|s| s.as_str()).collect::<Vec<_>>().join(", ");
            out.push(format!("[확인] Group Policy Registry.pol에 주의 문자열 발견: {} [{}]", path.display(), labels));
        }
    }
    out.push(format!("[정보] Group Policy Registry.pol {}개 확인, 주의 문자열 포함 {}개", existing, suspicious_files));
}

fn decode_registry_pol(bytes: &[u8]) -> String {
    let body = if bytes.len() > 4 { &bytes[4..] } else { bytes };
    let u16s: Vec<u16> = body.chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&u16s)
}

fn scan_extension_metadata(out: &mut Vec<String>) {
    let Ok(local) = env::var("LOCALAPPDATA") else { return; };
    let base = PathBuf::from(local);
    let browsers = [
        ("Chrome", base.join("Google\\Chrome\\User Data")),
        ("Edge", base.join("Microsoft\\Edge\\User Data")),
    ];

    let mut total = 0usize;
    let mut unusual_id = 0usize;
    let mut external_update = 0usize;
    let mut background = 0usize;

    for (browser, user_data) in browsers {
        let Ok(profiles) = fs::read_dir(user_data) else { continue; };
        for profile in profiles.flatten() {
            let profile_name = profile.file_name().to_string_lossy().to_string();
            if profile_name != "Default" && !profile_name.starts_with("Profile ") { continue; }
            let ext_root = profile.path().join("Extensions");
            let Ok(exts) = fs::read_dir(ext_root) else { continue; };
            for ext in exts.flatten() {
                if !ext.path().is_dir() { continue; }
                total += 1;
                let id = ext.file_name().to_string_lossy().to_string();
                if !valid_chromium_extension_id(&id) {
                    unusual_id += 1;
                    out.push(format!("[확인] {} {} 비표준 확장 ID: {}", browser, profile_name, compact(&id, 80)));
                }
                let Some(manifest) = newest_manifest(&ext.path()) else { continue; };
                let Ok(text) = fs::read_to_string(manifest) else { continue; };
                let name = json_string(&text, "name").unwrap_or_else(|| "(이름 확인 불가)".into());
                if text.contains("\"background\"") {
                    background += 1;
                }
                if let Some(url) = json_string(&text, "update_url") {
                    let lower = url.to_ascii_lowercase();
                    let official = lower.contains("google.com/service/update2/crx")
                        || lower.contains("edge.microsoft.com/extensionwebstorebase")
                        || lower.contains("clients2.google.com/service/update2/crx");
                    if !official {
                        external_update += 1;
                        out.push(format!("[확인] {} 확장 외부 update_url: {} ({})", browser, compact(&name, 55), compact(&url, 100)));
                    }
                }
            }
        }
    }
    out.push(format!(
        "[정보] Chromium 확장 {}개 메타데이터 확인 / 비표준 ID {} / 외부 update_url {} / background 선언 {}",
        total, unusual_id, external_update, background
    ));
}

fn newest_manifest(extension_dir: &Path) -> Option<PathBuf> {
    let items = fs::read_dir(extension_dir).ok()?;
    let mut dirs: Vec<PathBuf> = items.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
    dirs.sort_by(|a, b| b.file_name().cmp(&a.file_name()));
    for dir in dirs {
        let manifest = dir.join("manifest.json");
        if manifest.exists() { return Some(manifest); }
    }
    None
}

fn valid_chromium_extension_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b))
}

fn json_string(text: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\"", key);
    let start = text.find(&needle)? + needle.len();
    let rest = text.get(start..)?;
    let colon = rest.find(':')?;
    let after = rest.get(colon + 1..)?.trim_start().strip_prefix('"')?;
    let mut value = String::new();
    let mut escaped = false;
    for ch in after.chars() {
        if escaped {
            value.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            return Some(value);
        } else {
            value.push(ch);
        }
    }
    None
}

fn is_exec_like(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else { return false; };
    matches!(ext.to_ascii_lowercase().as_str(),
        "exe" | "dll" | "sys" | "scr" | "com" | "bat" | "cmd" | "vbs" | "js" | "ps1" | "hta")
}

fn compact(text: &str, max_chars: usize) -> String {
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max_chars { return flat; }
    let mut s: String = flat.chars().take(max_chars.saturating_sub(3)).collect();
    s.push_str("...");
    s
}
