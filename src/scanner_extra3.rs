use crate::rules::Rules;
use std::env;
use std::fs;
use std::os::windows::fs::MetadataExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
const FILE_ATTRIBUTE_SYSTEM: u32 = 0x0000_0004;

pub fn run_extra_scan3() -> Vec<String> {
    let rules = Rules::load();
    let mut out = Vec::with_capacity(64);
    out.push("--- MZ 격차 보완 점검 ---".to_string());
    scan_active_setup(&mut out, &rules);
    scan_user_com_persistence(&mut out, &rules);
    scan_hidden_executables(&mut out);
    scan_browser_notifications(&mut out);
    out
}

fn command_output(program: &str, args: &[&str]) -> String {
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
        let u16s: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16_lossy(&u16s);
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        let u16s: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16_lossy(&u16s);
    }
    String::from_utf8_lossy(bytes).into_owned()
}

fn scan_active_setup(out: &mut Vec<String>, rules: &Rules) {
    const KEYS: &[(&str, &str)] = &[
        ("HKCU Active Setup", "HKCU\\Software\\Microsoft\\Active Setup\\Installed Components"),
        ("HKLM Active Setup", "HKLM\\Software\\Microsoft\\Active Setup\\Installed Components"),
        ("HKLM 32-bit Active Setup", "HKLM\\Software\\WOW6432Node\\Microsoft\\Active Setup\\Installed Components"),
    ];

    let mut total = 0usize;
    let mut suspicious = 0usize;
    for &(label, key) in KEYS {
        let text = command_output("reg.exe", &["query", key, "/s", "/v", "StubPath"]);
        for line in text.lines().map(str::trim) {
            let lower = line.to_ascii_lowercase();
            if !lower.contains("stubpath") || !(line.contains("REG_SZ") || line.contains("REG_EXPAND_SZ")) {
                continue;
            }
            total += 1;
            if rules.autorun_is_suspicious(line) {
                suspicious += 1;
                out.push(format!("[주의] {} StubPath: {}", label, compact(line, 130)));
            }
        }
    }
    out.push(format!("[정보] Active Setup StubPath {}개 검사, 주의 {}개", total, suspicious));
}

fn scan_user_com_persistence(out: &mut Vec<String>, rules: &Rules) {
    // HKCU COM registrations are a particularly useful clean-room target because
    // per-user registrations can override machine-wide COM behavior without admin rights.
    const KEYS: &[(&str, &str)] = &[
        ("CLSID", "HKCU\\Software\\Classes\\CLSID"),
        ("WOW64 CLSID", "HKCU\\Software\\Classes\\WOW6432Node\\CLSID"),
        ("TypeLib", "HKCU\\Software\\Classes\\TypeLib"),
        ("Interface", "HKCU\\Software\\Classes\\Interface"),
    ];

    let mut values = 0usize;
    let mut suspicious = 0usize;
    for &(label, key) in KEYS {
        let text = command_output("reg.exe", &["query", key, "/s"]);
        if text.is_empty() { continue; }
        let mut current_key = String::new();
        for raw in text.lines() {
            let line = raw.trim();
            if line.starts_with("HKEY_") {
                current_key.clear();
                current_key.push_str(line);
                continue;
            }
            if !(line.contains("REG_SZ") || line.contains("REG_EXPAND_SZ")) {
                continue;
            }
            values += 1;
            if rules.path_is_suspicious(line) || rules.command_is_suspicious(line) {
                suspicious += 1;
                out.push(format!(
                    "[주의] 사용자 COM {}: {} -> {}",
                    label,
                    compact(&current_key, 82),
                    compact(line, 100)
                ));
                if suspicious >= 30 {
                    out.push("[정보] COM 주의 항목이 많아 추가 출력은 생략합니다.".into());
                    out.push(format!("[정보] 사용자 COM 값 {}개 이상 검사", values));
                    return;
                }
            }
        }
    }
    out.push(format!("[정보] 사용자 COM 등록 값 {}개 검사, 주의 {}개", values, suspicious));
}

fn scan_hidden_executables(out: &mut Vec<String>) {
    let mut roots: Vec<(&'static str, PathBuf)> = Vec::new();
    if let Ok(profile) = env::var("USERPROFILE") {
        roots.push(("사용자 프로필", PathBuf::from(profile)));
    }
    if let Ok(appdata) = env::var("APPDATA") {
        roots.push(("AppData Roaming", PathBuf::from(appdata)));
    }
    if let Ok(local) = env::var("LOCALAPPDATA") {
        roots.push(("AppData Local", PathBuf::from(local)));
    }
    if let Ok(drive) = env::var("SystemDrive") {
        roots.push(("시스템 드라이브 루트", PathBuf::from(format!("{}\\", drive))));
    }

    let mut hidden_exec = 0usize;
    let mut super_hidden_exec = 0usize;
    let mut shown = 0usize;
    for (label, root) in roots {
        let Ok(items) = fs::read_dir(&root) else { continue; };
        for item in items.flatten() {
            let path = item.path();
            if !is_interesting_executable(&path) { continue; }
            let Ok(meta) = item.metadata() else { continue; };
            if !meta.is_file() { continue; }
            let attrs = meta.file_attributes();
            let hidden = attrs & FILE_ATTRIBUTE_HIDDEN != 0;
            let system = attrs & FILE_ATTRIBUTE_SYSTEM != 0;
            if !hidden { continue; }
            hidden_exec += 1;
            if system { super_hidden_exec += 1; }
            if shown < 20 {
                out.push(format!(
                    "{} 숨김 실행 가능 파일({}): {}",
                    if system { "[주의]" } else { "[확인]" },
                    label,
                    compact(&path.to_string_lossy(), 130)
                ));
                shown += 1;
            }
        }
    }
    out.push(format!(
        "[정보] 선택 위치 숨김 실행 가능 파일 {}개 (숨김+시스템 {}개)",
        hidden_exec, super_hidden_exec
    ));
}

fn is_interesting_executable(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else { return false; };
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "exe" | "dll" | "scr" | "com" | "bat" | "cmd" | "vbs" | "vbe" | "js" | "jse" | "ps1" | "hta" | "lnk"
    )
}

fn scan_browser_notifications(out: &mut Vec<String>) {
    let Ok(local) = env::var("LOCALAPPDATA") else {
        out.push("[정보] 브라우저 알림: LOCALAPPDATA 확인 불가".into());
        return;
    };
    let local = PathBuf::from(local);
    let browsers = [
        ("Chrome", local.join("Google\\Chrome\\User Data")),
        ("Edge", local.join("Microsoft\\Edge\\User Data")),
    ];

    let mut allowed_total = 0usize;
    for (browser, user_data) in browsers {
        let Ok(profiles) = fs::read_dir(&user_data) else { continue; };
        for profile in profiles.flatten() {
            let name = profile.file_name().to_string_lossy().to_string();
            if name != "Default" && !name.starts_with("Profile ") { continue; }
            let preferences = profile.path().join("Preferences");
            let Ok(text) = fs::read_to_string(&preferences) else { continue; };
            let allowed = count_allowed_notifications(&text);
            if allowed > 0 {
                allowed_total += allowed;
                out.push(format!("[확인] {} {}: 허용된 사이트 알림 설정 약 {}개", browser, name, allowed));
            }
        }
    }
    if allowed_total == 0 {
        out.push("[정보] Chrome/Edge 허용 사이트 알림 설정을 찾지 못했습니다.".into());
    } else {
        out.push(format!("[정보] 허용 사이트 알림 설정 합계 약 {}개 - 원치 않는 광고 알림이면 검토 필요", allowed_total));
    }
}

fn count_allowed_notifications(text: &str) -> usize {
    // Chromium stores site-specific notification permissions in the
    // content_settings.exceptions.notifications object. This tiny parser only
    // extracts that object's balanced braces and counts setting=1 entries.
    let needle = "\"notifications\"";
    let Some(pos) = text.find(needle) else { return 0; };
    let Some(relative_open) = text[pos + needle.len()..].find('{') else { return 0; };
    let start = pos + needle.len() + relative_open;
    let Some(end) = matching_brace(text.as_bytes(), start) else { return 0; };
    let section = &text[start..=end];
    count_setting_one(section)
}

fn matching_brace(bytes: &[u8], start: usize) -> Option<usize> {
    if *bytes.get(start)? != b'{' { return None; }
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (index, &b) in bytes.iter().enumerate().skip(start) {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        if b == b'"' {
            in_string = true;
            continue;
        }
        if b == b'{' {
            depth += 1;
        } else if b == b'}' {
            depth = depth.saturating_sub(1);
            if depth == 0 { return Some(index); }
        }
    }
    None
}

fn count_setting_one(section: &str) -> usize {
    let mut count = 0usize;
    let mut rest = section;
    while let Some(pos) = rest.find("\"setting\"") {
        rest = &rest[pos + 9..];
        let Some(colon) = rest.find(':') else { break; };
        rest = &rest[colon + 1..];
        let trimmed = rest.trim_start();
        if trimmed.starts_with('1') {
            count += 1;
        }
        rest = trimmed.get(1..).unwrap_or("");
    }
    count
}

fn compact(text: &str, max_chars: usize) -> String {
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max_chars { return flat; }
    let mut s: String = flat.chars().take(max_chars.saturating_sub(3)).collect();
    s.push_str("...");
    s
}
