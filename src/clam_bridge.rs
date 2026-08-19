use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const UPDATE_INTERVAL_SECS: u64 = 24 * 60 * 60;

pub fn scan_candidates() -> Vec<String> {
    let mut out = Vec::with_capacity(32);
    out.push("--- 선택형 ClamAV PUA 보조 검사 ---".into());

    let Some(clamscan) = find_clamscan() else {
        out.push("[정보] ClamAV 미설치/미탐지 - 건너뜁니다. QuietGuard 기본 검사는 그대로 동작합니다.".into());
        return out;
    };

    let candidates = collect_candidates();
    if candidates.is_empty() {
        out.push(format!("[정보] ClamAV 발견: {}", clamscan.display()));
        out.push("[정보] 현재 자동실행/서비스 영역에서 ClamAV 보조 검사 대상 파일이 없습니다.".into());
        return out;
    }

    let mut cmd = Command::new(&clamscan);
    cmd.args(["--detect-pua", "--infected", "--no-summary", "--stdout"]);
    for path in candidates.iter().take(24) { cmd.arg(path); }
    cmd.creation_flags(CREATE_NO_WINDOW);

    let result = match cmd.output() {
        Ok(v) => v,
        Err(e) => {
            out.push(format!("[경고] ClamAV 실행 실패: {}", e));
            return out;
        }
    };

    out.push(format!("[정보] ClamAV PUA 검사 대상 {}개 (최대 24개)", candidates.len().min(24)));
    let text = decode_output(&result.stdout);
    let mut found = 0usize;
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if line.ends_with(" FOUND") || line.contains("PUA.") {
            found += 1;
            out.push(format!("[주의-ClamAV] {}", compact(line, 180)));
        }
    }

    if found == 0 && result.status.code() != Some(2) {
        out.push("[정상] 선택된 파일에서 ClamAV PUA/악성 시그니처 일치가 없습니다.".into());
    } else if result.status.code() == Some(2) {
        let err = decode_output(&result.stderr);
        out.push(format!("[경고] ClamAV 일부 검사 오류: {}", compact(err.trim(), 180)));
    }
    out
}

pub fn update_if_present(force: bool) -> Vec<String> {
    let mut out = Vec::with_capacity(8);
    let Some(clamscan) = find_clamscan() else {
        out.push("[정보] ClamAV 미설치 - ClamAV DB 업데이트 생략".into());
        return out;
    };
    out.push(format!("[정보] ClamAV 발견: {}", clamscan.display()));

    if !force && !clam_update_due() {
        out.push("[최신] ClamAV 업데이트 확인은 24시간 이내 수행되었습니다.".into());
        return out;
    }

    let Some(freshclam) = find_freshclam(&clamscan) else {
        out.push("[정보] freshclam.exe를 찾지 못해 ClamAV DB 자동 갱신은 생략합니다.".into());
        return out;
    };

    let mut cmd = Command::new(&freshclam);
    cmd.arg("--quiet");
    cmd.creation_flags(CREATE_NO_WINDOW);
    match cmd.output() {
        Ok(result) if result.status.success() => {
            let _ = fs::create_dir_all(data_dir());
            let _ = fs::write(data_dir().join("clamav-last-update.txt"), format!("{}\n", unix_now()));
            out.push("[완료] FreshClam 공식 시그니처 업데이트 확인 완료".into());
        }
        Ok(result) => {
            let err = decode_output(&result.stderr);
            let stdout = decode_output(&result.stdout);
            let detail = if !err.trim().is_empty() { err } else { stdout };
            out.push(format!("[정보] FreshClam 업데이트를 완료하지 못했습니다: {}", compact(detail.trim(), 180)));
            out.push("QuietGuard 자체/공개 DB 업데이트에는 영향이 없습니다.".into());
        }
        Err(e) => out.push(format!("[정보] FreshClam 실행 실패: {}", e)),
    }
    out
}

pub fn status_line() -> String {
    match find_clamscan() {
        Some(path) => format!("ClamAV 보조 검사: 사용 가능 ({})", path.display()),
        None => "ClamAV 보조 검사: 미설치/비활성 (선택 사항)".into(),
    }
}

fn collect_candidates() -> Vec<PathBuf> {
    let mut set = BTreeSet::new();
    const REG_QUERIES: &[&[&str]] = &[
        &["query", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
        &["query", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"],
        &["query", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
        &["query", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"],
        &["query", "HKLM\\SYSTEM\\CurrentControlSet\\Services", "/s", "/v", "ImagePath"],
        &["query", "HKLM\\SYSTEM\\CurrentControlSet\\Services", "/s", "/v", "ServiceDll"],
    ];

    for args in REG_QUERIES {
        let text = hidden_text("reg.exe", args);
        for line in text.lines() {
            if !(line.contains("REG_SZ") || line.contains("REG_EXPAND_SZ")) { continue; }
            if let Some(value) = registry_tail(line) {
                if let Some(path) = extract_existing_file(value) { set.insert(path); }
            }
        }
    }

    for startup in startup_dirs() {
        if let Ok(entries) = fs::read_dir(startup) {
            for entry in entries.flatten().take(80) {
                let path = entry.path();
                if path.is_file() && interesting_extension(&path) { set.insert(path); }
            }
        }
    }
    set.into_iter().collect()
}

fn startup_dirs() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(appdata) = env::var("APPDATA") {
        out.push(PathBuf::from(appdata).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup"));
    }
    if let Ok(programdata) = env::var("ProgramData") {
        out.push(PathBuf::from(programdata).join("Microsoft\\Windows\\Start Menu\\Programs\\StartUp"));
    }
    out
}

fn extract_existing_file(command: &str) -> Option<PathBuf> {
    let expanded = expand_env(command.trim());
    let text = expanded.trim();
    let first = if let Some(rest) = text.strip_prefix('"') {
        &rest[..rest.find('"')?]
    } else {
        text.split_whitespace().next()?
    };
    let candidate = normalize_nt(PathBuf::from(first.trim_matches('"')));
    if candidate.is_file() { return Some(candidate); }

    let lower = text.to_ascii_lowercase();
    for ext in [".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js"] {
        if let Some(pos) = lower.find(ext) {
            let end = pos + ext.len();
            let path = normalize_nt(PathBuf::from(text[..end].trim_matches('"')));
            if path.is_file() { return Some(path); }
        }
    }
    None
}

fn registry_tail(line: &str) -> Option<&str> {
    if let Some((_, tail)) = line.split_once("REG_EXPAND_SZ") { Some(tail.trim()) }
    else if let Some((_, tail)) = line.split_once("REG_SZ") { Some(tail.trim()) }
    else { None }
}

fn expand_env(text: &str) -> String {
    let mut result = text.to_string();
    for (name, value) in env::vars() {
        let needle = format!("%{}%", name);
        result = replace_ascii_case(&result, &needle, &value);
    }
    result
}

fn replace_ascii_case(source: &str, needle: &str, replacement: &str) -> String {
    let lower = source.to_ascii_lowercase();
    let needle_lower = needle.to_ascii_lowercase();
    if let Some(pos) = lower.find(&needle_lower) {
        let mut out = String::with_capacity(source.len() + replacement.len());
        out.push_str(&source[..pos]);
        out.push_str(replacement);
        out.push_str(&source[pos + needle.len()..]);
        out
    } else { source.to_string() }
}

fn normalize_nt(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix("\\??\\") { PathBuf::from(rest) } else { path }
}

fn interesting_extension(path: &Path) -> bool {
    matches!(path.extension().and_then(|s| s.to_str()).map(|s| s.to_ascii_lowercase()).as_deref(),
        Some("exe" | "dll" | "sys" | "scr" | "com" | "bat" | "cmd" | "ps1" | "vbs" | "js" | "jse" | "wsf" | "hta"))
}

fn find_clamscan() -> Option<PathBuf> {
    if let Ok(custom) = env::var("QUIETGUARD_CLAMSCAN") {
        let path = PathBuf::from(custom);
        if path.is_file() { return Some(path); }
    }
    if let Some(path) = where_exe("clamscan.exe") { return Some(path); }
    for root in [env::var("ProgramFiles").ok(), env::var("ProgramFiles(x86)").ok()] {
        if let Some(root) = root {
            let path = PathBuf::from(root).join("ClamAV\\clamscan.exe");
            if path.is_file() { return Some(path); }
        }
    }
    None
}

fn find_freshclam(clamscan: &Path) -> Option<PathBuf> {
    if let Some(parent) = clamscan.parent() {
        let path = parent.join("freshclam.exe");
        if path.is_file() { return Some(path); }
    }
    where_exe("freshclam.exe")
}

fn where_exe(name: &str) -> Option<PathBuf> {
    let output = hidden_output("where.exe", &[name]).ok()?;
    if !output.status.success() { return None; }
    decode_output(&output.stdout).lines().map(str::trim).filter(|s| !s.is_empty())
        .map(PathBuf::from).find(|p| p.is_file())
}

fn clam_update_due() -> bool {
    let Some(ts) = fs::read_to_string(data_dir().join("clamav-last-update.txt")).ok()
        .and_then(|s| s.trim().parse::<u64>().ok()) else { return true; };
    unix_now().saturating_sub(ts) >= UPDATE_INTERVAL_SECS
}

fn hidden_text(program: &str, args: &[&str]) -> String {
    hidden_output(program, args).map(|o| decode_output(&o.stdout)).unwrap_or_default()
}

fn hidden_output(program: &str, args: &[&str]) -> std::io::Result<Output> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.output()
}

fn decode_output(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xFF, 0xFE]) {
        let u16s: Vec<u16> = bytes[2..].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        return String::from_utf16_lossy(&u16s);
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        let u16s: Vec<u16> = bytes[2..].chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
        return String::from_utf16_lossy(&u16s);
    }
    String::from_utf8_lossy(bytes).into_owned()
}

fn data_dir() -> PathBuf {
    if let Ok(local) = env::var("LOCALAPPDATA") { return PathBuf::from(local).join("QuietGuard"); }
    PathBuf::from("QuietGuardData")
}
fn unix_now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) }
fn compact(text: &str, max: usize) -> String {
    let flat = text.replace(['\r', '\n'], " ");
    if flat.chars().count() <= max { flat } else { flat.chars().take(max).collect::<String>() + "..." }
}
