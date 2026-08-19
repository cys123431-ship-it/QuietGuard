use crate::rules::Rules;
use std::env;
use std::fs;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub fn run_extra_scan5() -> Vec<String> {
    let rules = Rules::load();
    let mut out = Vec::with_capacity(96);
    out.push("--- 서비스/드라이버·Firefox·알림 세부 점검 ---".into());
    scan_service_driver_combinations(&mut out, &rules);
    scan_firefox_extensions_and_policies(&mut out);
    scan_notification_origins(&mut out);
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

#[derive(Default)]
struct ServiceRecord {
    key: String,
    image_path: String,
    start: Option<u32>,
    service_type: Option<u32>,
}

fn scan_service_driver_combinations(out: &mut Vec<String>, rules: &Rules) {
    let text = hidden_output("reg.exe", &[
        "query", "HKLM\\SYSTEM\\CurrentControlSet\\Services", "/s"
    ]);
    if text.is_empty() {
        out.push("[정보] 서비스/드라이버 전체 구성을 읽지 못했습니다.".into());
        return;
    }

    let mut current = ServiceRecord::default();
    let mut records = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with("HKEY_") {
            if !current.key.is_empty() && !current.image_path.is_empty() {
                records.push(current);
            }
            current = ServiceRecord::default();
            current.key = line.to_string();
            continue;
        }
        if line.contains("ImagePath") && (line.contains("REG_SZ") || line.contains("REG_EXPAND_SZ")) {
            current.image_path = registry_tail(line).unwrap_or("").to_string();
        } else if line.contains("REG_DWORD") && line.starts_with("Start") {
            current.start = parse_reg_dword(line);
        } else if line.contains("REG_DWORD") && line.starts_with("Type") {
            current.service_type = parse_reg_dword(line);
        }
    }
    if !current.key.is_empty() && !current.image_path.is_empty() {
        records.push(current);
    }

    let mut suspicious = 0usize;
    let mut driver_nonstandard = 0usize;
    let mut auto_user_writable = 0usize;
    for record in &records {
        let lower_path = expand_common_env(&record.image_path).to_ascii_lowercase();
        let is_driver = record.service_type.map(|v| v & 0x3 != 0).unwrap_or(false);
        let auto_start = record.start == Some(2) || record.start == Some(0) || record.start == Some(1);

        if rules.path_is_suspicious(&lower_path) {
            suspicious += 1;
            if auto_start { auto_user_writable += 1; }
            out.push(format!(
                "[주의] 서비스/드라이버 의심 경로{}: {} -> {}",
                if auto_start { " (자동/부팅 시작)" } else { "" },
                compact(last_key_component(&record.key), 55),
                compact(&record.image_path, 120)
            ));
        }

        if is_driver && !driver_path_looks_standard(&lower_path) {
            driver_nonstandard += 1;
            if driver_nonstandard <= 20 {
                out.push(format!(
                    "[확인] 드라이버 비표준 경로: {} -> {}",
                    compact(last_key_component(&record.key), 55),
                    compact(&record.image_path, 120)
                ));
            }
        }
    }

    out.push(format!(
        "[정보] ImagePath 있는 서비스/드라이버 {}개 분석 / 의심 경로 {} / 자동·부팅 시작 의심 {} / 비표준 드라이버 경로 {}",
        records.len(), suspicious, auto_user_writable, driver_nonstandard
    ));
}

fn driver_path_looks_standard(path: &str) -> bool {
    let normalized = path.replace('/', "\\");
    normalized.contains("\\windows\\system32\\drivers\\")
        || normalized.contains("\\systemroot\\system32\\drivers\\")
        || normalized.starts_with("system32\\drivers\\")
        || normalized.starts_with("\\??\\c:\\windows\\system32\\drivers\\")
}

fn expand_common_env(text: &str) -> String {
    let mut result = text.to_string();
    if let Ok(windir) = env::var("WINDIR") {
        result = replace_case_insensitive(&result, "%windir%", &windir);
        result = replace_case_insensitive(&result, "%systemroot%", &windir);
    }
    if let Ok(programdata) = env::var("ProgramData") {
        result = replace_case_insensitive(&result, "%programdata%", &programdata);
    }
    if let Ok(local) = env::var("LOCALAPPDATA") {
        result = replace_case_insensitive(&result, "%localappdata%", &local);
    }
    if let Ok(appdata) = env::var("APPDATA") {
        result = replace_case_insensitive(&result, "%appdata%", &appdata);
    }
    result
}

fn replace_case_insensitive(source: &str, needle: &str, replacement: &str) -> String {
    let lower = source.to_ascii_lowercase();
    let needle_lower = needle.to_ascii_lowercase();
    if let Some(pos) = lower.find(&needle_lower) {
        let mut out = String::with_capacity(source.len() + replacement.len());
        out.push_str(&source[..pos]);
        out.push_str(replacement);
        out.push_str(&source[pos + needle.len()..]);
        out
    } else {
        source.to_string()
    }
}

fn parse_reg_dword(line: &str) -> Option<u32> {
    let pos = line.find("REG_DWORD")?;
    let value = line[pos + "REG_DWORD".len()..].trim();
    if let Some(hex) = value.strip_prefix("0x") {
        u32::from_str_radix(hex.split_whitespace().next()?, 16).ok()
    } else {
        value.split_whitespace().next()?.parse().ok()
    }
}

fn registry_tail(line: &str) -> Option<&str> {
    if let Some((_, tail)) = line.split_once("REG_EXPAND_SZ") {
        Some(tail.trim())
    } else if let Some((_, tail)) = line.split_once("REG_SZ") {
        Some(tail.trim())
    } else {
        None
    }
}

fn last_key_component(key: &str) -> &str {
    key.rsplit('\\').next().unwrap_or(key)
}

fn scan_firefox_extensions_and_policies(out: &mut Vec<String>) {
    let mut profiles = 0usize;
    let mut addons = 0usize;
    let mut unsigned_or_unknown = 0usize;
    let mut external_sources = 0usize;

    if let Ok(appdata) = env::var("APPDATA") {
        let root = PathBuf::from(appdata).join("Mozilla\\Firefox\\Profiles");
        if let Ok(items) = fs::read_dir(root) {
            for item in items.flatten() {
                if !item.path().is_dir() { continue; }
                profiles += 1;
                let extensions_json = item.path().join("extensions.json");
                let Ok(text) = fs::read_to_string(&extensions_json) else { continue; };
                let blocks = split_json_objects_for_key(&text, "addons");
                for block in blocks {
                    addons += 1;
                    let id = json_string(block, "id").unwrap_or_else(|| "(id 없음)".into());
                    let active = json_bool(block, "active").unwrap_or(false);
                    let signed_state = json_i32(block, "signedState");
                    if active && signed_state.map(|v| v <= 0).unwrap_or(true) {
                        unsigned_or_unknown += 1;
                        if unsigned_or_unknown <= 20 {
                            out.push(format!("[확인] Firefox 활성 확장 서명상태 확인 필요: {} (signedState={:?})", compact(&id, 85), signed_state));
                        }
                    }
                    if let Some(source) = json_string(block, "sourceURI") {
                        if !source.is_empty() && !source.starts_with("https://addons.mozilla.org/") && !source.starts_with("moz-extension://") {
                            external_sources += 1;
                            if external_sources <= 20 {
                                out.push(format!("[확인] Firefox 확장 외부 sourceURI: {} -> {}", compact(&id, 60), compact(&source, 100)));
                            }
                        }
                    }
                }
            }
        }
    }

    let policy_keys = [
        ("Firefox 사용자 정책", "HKCU\\Software\\Policies\\Mozilla\\Firefox"),
        ("Firefox 시스템 정책", "HKLM\\Software\\Policies\\Mozilla\\Firefox"),
    ];
    let mut policy_values = 0usize;
    for (label, key) in policy_keys {
        let text = hidden_output("reg.exe", &["query", key, "/s"]);
        let count = text.lines().filter(|l| l.contains("REG_")).count();
        if count > 0 {
            policy_values += count;
            out.push(format!("[확인] {} 값 {}개", label, count));
        }
    }

    out.push(format!(
        "[정보] Firefox 프로필 {} / 확장 메타데이터 {} / 활성 확장 서명상태 확인필요 {} / 외부 sourceURI {} / 정책 값 {}",
        profiles, addons, unsigned_or_unknown, external_sources, policy_values
    ));
}

fn split_json_objects_for_key<'a>(text: &'a str, key: &str) -> Vec<&'a str> {
    let needle = format!("\"{}\"", key);
    let Some(key_pos) = text.find(&needle) else { return Vec::new(); };
    let Some(array_rel) = text[key_pos + needle.len()..].find('[') else { return Vec::new(); };
    let start = key_pos + needle.len() + array_rel;
    let Some(end) = matching_delimiter(text.as_bytes(), start, b'[', b']') else { return Vec::new(); };
    let bytes = text.as_bytes();
    let mut result = Vec::new();
    let mut i = start + 1;
    while i < end {
        if bytes[i] == b'{' {
            if let Some(obj_end) = matching_delimiter(bytes, i, b'{', b'}') {
                result.push(&text[i..=obj_end]);
                i = obj_end + 1;
                continue;
            }
        }
        i += 1;
    }
    result
}

fn scan_notification_origins(out: &mut Vec<String>) {
    let Ok(local) = env::var("LOCALAPPDATA") else { return; };
    let base = PathBuf::from(local);
    let browsers = [
        ("Chrome", base.join("Google\\Chrome\\User Data")),
        ("Edge", base.join("Microsoft\\Edge\\User Data")),
    ];

    let mut total_allowed = 0usize;
    let mut shown = 0usize;
    for (browser, user_data) in browsers {
        let Ok(profiles) = fs::read_dir(user_data) else { continue; };
        for profile in profiles.flatten() {
            let profile_name = profile.file_name().to_string_lossy().to_string();
            if profile_name != "Default" && !profile_name.starts_with("Profile ") { continue; }
            let path = profile.path().join("Preferences");
            let Ok(text) = fs::read_to_string(path) else { continue; };
            for origin in allowed_notification_origins(&text) {
                total_allowed += 1;
                if shown < 30 {
                    out.push(format!("[확인] {} {} 알림 허용 사이트: {}", browser, profile_name, compact(&origin, 120)));
                    shown += 1;
                }
            }
        }
    }
    out.push(format!("[정보] Chrome/Edge 알림 허용 사이트 {}개", total_allowed));
}

fn allowed_notification_origins(text: &str) -> Vec<String> {
    let needle = "\"notifications\"";
    let Some(pos) = text.find(needle) else { return Vec::new(); };
    let Some(open_rel) = text[pos + needle.len()..].find('{') else { return Vec::new(); };
    let start = pos + needle.len() + open_rel;
    let Some(end) = matching_delimiter(text.as_bytes(), start, b'{', b'}') else { return Vec::new(); };
    let bytes = text.as_bytes();
    let mut result = Vec::new();
    let mut i = start + 1;

    while i < end {
        while i < end && matches!(bytes[i], b' ' | b'\r' | b'\n' | b'\t' | b',') { i += 1; }
        if i >= end || bytes[i] != b'"' { i += 1; continue; }
        let Some((key, after_key)) = parse_json_string_at(text, i) else { break; };
        i = after_key;
        while i < end && bytes[i].is_ascii_whitespace() { i += 1; }
        if i >= end || bytes[i] != b':' { continue; }
        i += 1;
        while i < end && bytes[i].is_ascii_whitespace() { i += 1; }
        if i < end && bytes[i] == b'{' {
            if let Some(obj_end) = matching_delimiter(bytes, i, b'{', b'}') {
                let block = &text[i..=obj_end];
                if json_i32(block, "setting") == Some(1) {
                    result.push(key);
                }
                i = obj_end + 1;
                continue;
            }
        }
        i += 1;
    }
    result
}

fn matching_delimiter(bytes: &[u8], start: usize, open: u8, close: u8) -> Option<usize> {
    if *bytes.get(start)? != open { return None; }
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (index, &b) in bytes.iter().enumerate().skip(start) {
        if in_string {
            if escaped { escaped = false; }
            else if b == b'\\' { escaped = true; }
            else if b == b'"' { in_string = false; }
            continue;
        }
        if b == b'"' { in_string = true; continue; }
        if b == open { depth += 1; }
        else if b == close {
            depth = depth.saturating_sub(1);
            if depth == 0 { return Some(index); }
        }
    }
    None
}

fn parse_json_string_at(text: &str, start: usize) -> Option<(String, usize)> {
    let bytes = text.as_bytes();
    if *bytes.get(start)? != b'"' { return None; }
    let mut value = String::new();
    let mut i = start + 1;
    let mut escaped = false;
    while i < bytes.len() {
        let b = bytes[i];
        if escaped {
            value.push(b as char);
            escaped = false;
        } else if b == b'\\' {
            escaped = true;
        } else if b == b'"' {
            return Some((value, i + 1));
        } else {
            value.push(b as char);
        }
        i += 1;
    }
    None
}

fn json_string(text: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\"", key);
    let start = text.find(&needle)? + needle.len();
    let rest = text.get(start..)?;
    let colon = rest.find(':')?;
    let quote_pos = start + colon + 1;
    let after = text.get(quote_pos..)?.trim_start();
    let absolute = text.len() - after.len();
    parse_json_string_at(text, absolute).map(|(v, _)| v)
}

fn json_bool(text: &str, key: &str) -> Option<bool> {
    let needle = format!("\"{}\"", key);
    let start = text.find(&needle)? + needle.len();
    let rest = text.get(start..)?;
    let colon = rest.find(':')?;
    let value = rest.get(colon + 1..)?.trim_start();
    if value.starts_with("true") { Some(true) }
    else if value.starts_with("false") { Some(false) }
    else { None }
}

fn json_i32(text: &str, key: &str) -> Option<i32> {
    let needle = format!("\"{}\"", key);
    let start = text.find(&needle)? + needle.len();
    let rest = text.get(start..)?;
    let colon = rest.find(':')?;
    let value = rest.get(colon + 1..)?.trim_start();
    let token: String = value.chars().take_while(|c| c.is_ascii_digit() || *c == '-').collect();
    token.parse().ok()
}

fn compact(text: &str, max_chars: usize) -> String {
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max_chars { return flat; }
    let mut s: String = flat.chars().take(max_chars.saturating_sub(3)).collect();
    s.push_str("...");
    s
}
