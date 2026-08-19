use crate::{intel, keyed_intel, regional_intel};
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub fn run_extra_scan8() -> Vec<String> {
    let mut out = Vec::with_capacity(120);
    out.push("--- 공개 PUP/애드웨어·선택형 위협 DB 대조 ---".into());
    out.extend(intel::status_lines());
    out.push(regional_intel::status_line());
    out.extend(keyed_intel::status_lines());

    let mut seen = BTreeSet::new();
    scan_registry_urls(&mut out, &mut seen);
    scan_browser_profiles(&mut out, &mut seen);
    scan_extension_manifests(&mut out, &mut seen);
    scan_task_urls(&mut out, &mut seen);

    if seen.is_empty() {
        out.push("[정상] 현재 확인한 설정/브라우저 영역에서 외부 DB 일치 도메인이 없습니다.".into());
    } else {
        out.push(format!("[정보] 외부 DB와 일치한 고유 소스/도메인 {}개", seen.len()));
    }
    out
}

fn scan_registry_urls(out: &mut Vec<String>, seen: &mut BTreeSet<String>) {
    const KEYS: &[(&str, &str)] = &[
        ("Internet Settings", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"),
        ("IE SearchScopes", "HKCU\\Software\\Microsoft\\Internet Explorer\\SearchScopes"),
        ("Chrome 사용자 정책", "HKCU\\Software\\Policies\\Google\\Chrome"),
        ("Chrome 시스템 정책", "HKLM\\Software\\Policies\\Google\\Chrome"),
        ("Edge 사용자 정책", "HKCU\\Software\\Policies\\Microsoft\\Edge"),
        ("Edge 시스템 정책", "HKLM\\Software\\Policies\\Microsoft\\Edge"),
    ];
    for &(label, key) in KEYS {
        let text = hidden_output("reg.exe", &["query", key, "/s"]);
        if !text.is_empty() { inspect_text(label, &text, out, seen, 20); }
    }
}

fn scan_browser_profiles(out: &mut Vec<String>, seen: &mut BTreeSet<String>) {
    let Ok(local) = env::var("LOCALAPPDATA") else { return; };
    let root = PathBuf::from(local);
    const BROWSERS: &[(&str, &str)] = &[("Chrome", "Google\\Chrome\\User Data"), ("Edge", "Microsoft\\Edge\\User Data")];
    for &(browser, relative) in BROWSERS {
        let base = root.join(relative);
        let Ok(entries) = fs::read_dir(&base) else { continue; };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name != "Default" && !name.starts_with("Profile ") { continue; }
            for file in ["Preferences", "Secure Preferences"] {
                if let Ok(text) = fs::read_to_string(entry.path().join(file)) {
                    inspect_text(&format!("{} {} {}", browser, name, file), &text, out, seen, 35);
                }
            }
        }
    }
}

fn scan_extension_manifests(out: &mut Vec<String>, seen: &mut BTreeSet<String>) {
    let Ok(local) = env::var("LOCALAPPDATA") else { return; };
    let root = PathBuf::from(local);
    const BROWSERS: &[(&str, &str)] = &[("Chrome", "Google\\Chrome\\User Data"), ("Edge", "Microsoft\\Edge\\User Data")];
    for &(browser, relative) in BROWSERS {
        let base = root.join(relative);
        let Ok(profiles) = fs::read_dir(&base) else { continue; };
        for profile in profiles.flatten() {
            let name = profile.file_name().to_string_lossy().to_string();
            if name != "Default" && !name.starts_with("Profile ") { continue; }
            let Ok(exts) = fs::read_dir(profile.path().join("Extensions")) else { continue; };
            for ext in exts.flatten().take(160) {
                if !ext.path().is_dir() { continue; }
                let Ok(versions) = fs::read_dir(ext.path()) else { continue; };
                for version in versions.flatten().take(8) {
                    if let Ok(text) = fs::read_to_string(version.path().join("manifest.json")) {
                        inspect_text(&format!("{} {} 확장", browser, name), &text, out, seen, 25);
                    }
                }
            }
        }
    }
}

fn scan_task_urls(out: &mut Vec<String>, seen: &mut BTreeSet<String>) {
    let text = hidden_output("schtasks.exe", &["/query", "/fo", "LIST", "/v"]);
    if !text.is_empty() { inspect_text("예약 작업", &text, out, seen, 20); }
}

fn inspect_text(label: &str, text: &str, out: &mut Vec<String>, seen: &mut BTreeSet<String>, max_new: usize) {
    let mut emitted = 0usize;
    for candidate in candidate_tokens(text) {
        for hit in intel::lookup_domain(&candidate) {
            let key = format!("{}|{}", hit.source, hit.matched_domain);
            if !seen.insert(key) { continue; }
            let prefix = if hit.source == "UncheckyAds" || hit.source == "KADhosts" { "[주의-외부DB]" } else { "[확인-외부DB]" };
            out.push(format!("{} {}: {} | {} ({})", prefix, label, hit.matched_domain, hit.source, hit.category));
            emitted += 1;
            if emitted >= max_new { return; }
        }
        if let Some(domain) = regional_intel::lookup_domain(&candidate) {
            let key = format!("YousList|{}", domain);
            if seen.insert(key) {
                out.push(format!("[참고-한국광고DB] {}: {} | YousList (광고 참고, 악성 판정 아님)", label, domain));
                emitted += 1;
                if emitted >= max_new { return; }
            }
        }
        for hit in keyed_intel::lookup_domain(&candidate) {
            let key = format!("{}|{}", hit.source, hit.matched_domain);
            if !seen.insert(key) { continue; }
            out.push(format!("[주의-위협DB] {}: {} | {} ({})", label, hit.matched_domain, hit.source, hit.category));
            emitted += 1;
            if emitted >= max_new { return; }
        }
    }
}

fn candidate_tokens(text: &str) -> Vec<String> {
    let mut set = BTreeSet::new();
    for scheme in ["http://", "https://", "ftp://"] {
        let mut offset = 0usize;
        while let Some(pos) = text[offset..].find(scheme) {
            let start = offset + pos;
            let rest = &text[start..];
            let end = rest.find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ')' | ']' | '}' | ',')).unwrap_or(rest.len());
            if end > scheme.len() { set.insert(rest[..end].trim_end_matches(|c: char| matches!(c, '.' | ';' | ':')).to_string()); }
            offset = start + scheme.len();
            if offset >= text.len() { break; }
        }
    }
    for raw in text.split_whitespace() {
        for piece in raw.split(|c| matches!(c, ';' | ',' | '=' | '|')) {
            let candidate = piece.trim_matches(|c: char| matches!(c, '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>' | ':' | '.'));
            if candidate.contains('.') && candidate.len() >= 4 && candidate.len() <= 300 { set.insert(candidate.to_string()); }
        }
    }
    set.into_iter().collect()
}

fn hidden_output(program: &str, args: &[&str]) -> String {
    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.creation_flags(CREATE_NO_WINDOW);
    match cmd.output() { Ok(o) => decode_output(&o.stdout), Err(_) => String::new() }
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
