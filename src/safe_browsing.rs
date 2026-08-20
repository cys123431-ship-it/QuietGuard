use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const MAX_URLS: usize = 50;

pub fn status_line() -> String {
    match config() {
        Some(_) => "Google Safe Browsing: 사용자가 명시적으로 활성화함 (URL 질의 가능)".into(),
        None => "Google Safe Browsing: 비활성 (기본값, URL 개인정보 보호)".into(),
    }
}

pub fn scan_opt_in() -> Vec<String> {
    let mut out = Vec::with_capacity(24);
    out.push("--- 선택형 Google Safe Browsing URL 점검 ---".into());
    let Some(key) = config() else {
        out.push("[정보] 기본 비활성 - URL을 외부 서비스로 보내지 않습니다.".into());
        return out;
    };

    let urls = collect_candidate_urls();
    if urls.is_empty() {
        out.push("[정보] Safe Browsing으로 확인할 설정/작업 URL이 없습니다.".into());
        return out;
    }

    let dir = data_dir().join("gsb");
    if let Err(e) = fs::create_dir_all(&dir) {
        out.push(format!("[오류] Safe Browsing 임시 폴더 생성 실패: {}", e));
        return out;
    }
    let input = dir.join("urls.tmp");
    let response = dir.join("response.tmp.json");
    let selected: Vec<&String> = urls.iter().take(MAX_URLS).collect();
    if let Err(e) = fs::write(&input, selected.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("\n") + "\n") {
        out.push(format!("[오류] Safe Browsing 입력 준비 실패: {}", e));
        return out;
    }

    let input_ps = ps_quote(&input.to_string_lossy());
    let response_ps = ps_quote(&response.to_string_lossy());
    let script = format!(
        "$ErrorActionPreference='Stop';$u=Get-Content -LiteralPath '{}';$p=@();foreach($x in $u){{if($x){{$p+=('urls='+[uri]::EscapeDataString($x))}}}};$uri='https://safebrowsing.googleapis.com/v5/urls:search?key='+[uri]::EscapeDataString($env:QUIETGUARD_GSB_KEY)+'&'+($p -join '&');Invoke-WebRequest -UseBasicParsing -TimeoutSec 45 -Headers @{{'Accept'='application/json'}} -Uri $uri -OutFile '{}';",
        input_ps, response_ps
    );
    let mut cmd = Command::new("powershell.exe");
    cmd.args(["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &script]);
    cmd.env("QUIETGUARD_GSB_KEY", key);
    cmd.creation_flags(CREATE_NO_WINDOW);
    let result = cmd.output();
    let _ = fs::remove_file(&input);

    match result {
        Ok(r) if r.status.success() => {}
        Ok(r) => {
            let err = String::from_utf8_lossy(&r.stderr);
            out.push(format!("[정보] Safe Browsing 질의 실패: {}", compact(err.trim(), 180)));
            let _ = fs::remove_file(&response);
            return out;
        }
        Err(e) => {
            out.push(format!("[정보] Safe Browsing 실행 실패: {}", e));
            return out;
        }
    }

    let text = fs::read_to_string(&response).unwrap_or_default();
    let _ = fs::remove_file(&response);
    let hits = parse_threats(&text);
    if hits.is_empty() {
        out.push(format!("[정상] Safe Browsing {}개 URL 질의에서 알려진 위협 일치 없음", selected.len()));
    } else {
        out.push(format!("[주의] Safe Browsing 위협 일치 {}개", hits.len()));
        for (url, types) in hits.into_iter().take(20) {
            let severity = if types.contains("UNWANTED_SOFTWARE") { "[주의-GSB-PUA]" } else { "[주의-GSB]" };
            out.push(format!("{} {} | {}", severity, compact(&url, 120), compact(&types, 80)));
        }
    }
    out
}

fn config() -> Option<String> {
    let env_enabled = env::var("QUIETGUARD_GSB_ENABLED").ok().map(|v| truthy(&v)).unwrap_or(false);
    let env_key = env::var("QUIETGUARD_GSB_KEY").ok().filter(|v| valid_key(v));
    if env_enabled { if let Some(key) = env_key { return Some(key); } }

    let text = fs::read_to_string(data_dir().join("secrets.conf")).ok()?;
    let mut enabled = false;
    let mut key = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        let Some((name, value)) = line.split_once('=') else { continue; };
        match name.trim().to_ascii_lowercase().as_str() {
            "google_safe_browsing_enabled" => enabled = truthy(value.trim()),
            "google_safe_browsing_key" => if valid_key(value.trim()) { key = Some(value.trim().to_string()); },
            _ => {}
        }
    }
    if enabled { key } else { None }
}

fn collect_candidate_urls() -> Vec<String> {
    let mut set = BTreeSet::new();
    const REG_KEYS: &[&str] = &[
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
        "HKCU\\Software\\Microsoft\\Internet Explorer\\SearchScopes",
        "HKCU\\Software\\Policies\\Google\\Chrome",
        "HKLM\\Software\\Policies\\Google\\Chrome",
        "HKCU\\Software\\Policies\\Microsoft\\Edge",
        "HKLM\\Software\\Policies\\Microsoft\\Edge",
    ];
    for key in REG_KEYS { harvest_urls(&hidden_text("reg.exe", &["query", key, "/s"]), &mut set); }
    harvest_urls(&hidden_text("schtasks.exe", &["/query", "/fo", "LIST", "/v"]), &mut set);

    if let Ok(local) = env::var("LOCALAPPDATA") {
        let base = PathBuf::from(local);
        for rel in ["Google\\Chrome\\User Data", "Microsoft\\Edge\\User Data"] {
            let root = base.join(rel);
            if let Ok(profiles) = fs::read_dir(root) {
                for profile in profiles.flatten().take(12) {
                    let name = profile.file_name().to_string_lossy().to_string();
                    if name != "Default" && !name.starts_with("Profile ") { continue; }
                    for file in ["Preferences", "Secure Preferences"] {
                        if let Ok(text) = fs::read_to_string(profile.path().join(file)) {
                            harvest_urls(&text, &mut set);
                            if set.len() >= MAX_URLS * 3 { break; }
                        }
                    }
                }
            }
        }
    }
    set.into_iter().take(MAX_URLS).collect()
}

fn harvest_urls(text: &str, set: &mut BTreeSet<String>) {
    for scheme in ["https://", "http://"] {
        let mut offset = 0usize;
        while let Some(pos) = text[offset..].find(scheme) {
            let start = offset + pos;
            let rest = &text[start..];
            let end = rest.find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ')' | ']' | '}' | ',' | '\\')).unwrap_or(rest.len());
            if end > scheme.len() {
                let value = rest[..end].trim_end_matches(|c: char| matches!(c, '.' | ';')).to_string();
                if value.len() <= 2048 { set.insert(value); }
            }
            offset = start + scheme.len();
            if offset >= text.len() || set.len() >= MAX_URLS * 3 { break; }
        }
    }
}

fn parse_threats(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while let Some(pos) = text[offset..].find("\"url\"") {
        let start = offset + pos;
        let block_end = text[start..].find('}').map(|v| start + v).unwrap_or(text.len());
        let block = &text[start..block_end];
        let Some(url) = json_string(block, "url") else { offset = block_end.saturating_add(1); continue; };
        let types = if block.contains("UNWANTED_SOFTWARE") { "UNWANTED_SOFTWARE" }
            else if block.contains("MALWARE") { "MALWARE" }
            else if block.contains("SOCIAL_ENGINEERING") { "SOCIAL_ENGINEERING" }
            else { "OTHER_THREAT" };
        out.push((url, types.to_string()));
        offset = block_end.saturating_add(1);
        if offset >= text.len() { break; }
    }
    out
}

fn json_string(text: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\"", key);
    let rest = &text[text.find(&needle)? + needle.len()..];
    let after = rest[rest.find(':')? + 1..].trim_start().strip_prefix('"')?;
    let mut escaped = false;
    for (i, c) in after.char_indices() {
        if escaped { escaped = false; continue; }
        if c == '\\' { escaped = true; continue; }
        if c == '"' { return Some(after[..i].replace("\\/", "/").replace("\\\\", "\\").replace("\\\"", "\"")); }
    }
    None
}

fn hidden_text(program: &str, args: &[&str]) -> String {
    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.output().map(|o| decode_output(&o.stdout)).unwrap_or_default()
}

fn decode_output(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xFF, 0xFE]) {
        let u16s: Vec<u16> = bytes[2..].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        return String::from_utf16_lossy(&u16s);
    }
    String::from_utf8_lossy(bytes).into_owned()
}

fn truthy(v: &str) -> bool { matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on") }
fn valid_key(v: &str) -> bool { v.len() >= 16 && v.len() <= 512 && !v.chars().any(char::is_whitespace) }
fn ps_quote(v: &str) -> String { v.replace('\'', "''") }
fn data_dir() -> PathBuf {
    if let Ok(local) = env::var("LOCALAPPDATA") { return PathBuf::from(local).join("QuietGuard"); }
    PathBuf::from("QuietGuardData")
}
fn compact(text: &str, max: usize) -> String {
    let flat = text.replace(['\r', '\n'], " ");
    if flat.chars().count() <= max { flat } else { flat.chars().take(max).collect::<String>() + "..." }
}
