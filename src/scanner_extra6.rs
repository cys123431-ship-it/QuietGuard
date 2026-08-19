use crate::rules::Rules;
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub fn run_extra_scan6() -> Vec<String> {
    let rules = Rules::load();
    let mut out = Vec::with_capacity(96);
    out.push("--- 머신 COM·전자서명 보조 점검 ---".into());
    scan_machine_com_targets(&mut out);
    scan_app_paths(&mut out, &rules);
    scan_suspicious_file_signatures(&mut out, &rules);
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
        let values: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16_lossy(&values);
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        let values: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16_lossy(&values);
    }
    String::from_utf8_lossy(bytes).into_owned()
}

fn scan_machine_com_targets(out: &mut Vec<String>) {
    const ROOTS: &[(&str, &str)] = &[
        ("HKLM CLSID", "HKLM\\Software\\Classes\\CLSID"),
        ("HKLM WOW64 CLSID", "HKLM\\Software\\Classes\\WOW6432Node\\CLSID"),
    ];
    const PATTERNS: &[&str] = &["AppData", "\\Temp\\", "\\Downloads\\", "\\Users\\Public\\"];

    let mut hits = BTreeSet::new();
    for &(label, root) in ROOTS {
        for &pattern in PATTERNS {
            let text = hidden_output("reg.exe", &[
                "query", root, "/s", "/f", pattern, "/d"
            ]);
            let mut current_key = String::new();
            for raw in text.lines() {
                let line = raw.trim();
                if line.starts_with("HKEY_") {
                    current_key.clear();
                    current_key.push_str(line);
                    continue;
                }
                if line.contains("REG_SZ") || line.contains("REG_EXPAND_SZ") {
                    let flat = compact(line, 120);
                    hits.insert(format!("{}|{}|{}", label, current_key, flat));
                }
            }
        }
    }

    if hits.is_empty() {
        out.push("[정보] 머신 CLSID에서 사용자 쓰기 가능 경로 패턴을 찾지 못했습니다.".into());
    } else {
        out.push(format!("[확인] 머신 CLSID 사용자 경로 패턴 일치 {}개", hits.len()));
        for item in hits.iter().take(30) {
            let mut parts = item.splitn(3, '|');
            let label = parts.next().unwrap_or("");
            let key = parts.next().unwrap_or("");
            let value = parts.next().unwrap_or("");
            out.push(format!("[확인] {}: {} -> {}", label, compact(key, 76), value));
        }
        if hits.len() > 30 {
            out.push(format!("[정보] 머신 CLSID 일치 항목 {}개 추가 출력 생략", hits.len() - 30));
        }
    }
}

fn scan_app_paths(out: &mut Vec<String>, rules: &Rules) {
    const KEYS: &[(&str, &str)] = &[
        ("HKCU App Paths", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"),
        ("HKLM App Paths", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"),
        ("HKLM 32-bit App Paths", "HKLM\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\App Paths"),
    ];

    let mut values = 0usize;
    let mut suspicious = 0usize;
    for &(label, key) in KEYS {
        let text = hidden_output("reg.exe", &["query", key, "/s"]);
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
            if rules.autorun_is_suspicious(line) {
                suspicious += 1;
                if suspicious <= 25 {
                    out.push(format!("[확인] {} 의심 경로: {} -> {}", label, compact(&current_key, 75), compact(line, 115)));
                }
            }
        }
    }
    out.push(format!("[정보] App Paths 값 {}개 검사, 의심 경로 {}개", values, suspicious));
}

fn scan_suspicious_file_signatures(out: &mut Vec<String>, rules: &Rules) {
    let candidates = collect_suspicious_file_candidates(rules);
    if candidates.is_empty() {
        out.push("[정보] 전자서명 확인 대상 의심 실행파일 없음".into());
        return;
    }

    out.push(format!("[정보] 전자서명 확인 대상 {}개 (최대 12개 검사)", candidates.len()));
    let mut valid = 0usize;
    let mut unsigned = 0usize;
    let mut warning = 0usize;
    let mut checked = 0usize;

    for path in candidates.iter().take(12) {
        if !path.is_file() { continue; }
        checked += 1;
        let Some((status, signer)) = authenticode(path) else {
            out.push(format!("[정보] 서명상태 조회 실패: {}", compact(&path.to_string_lossy(), 115)));
            continue;
        };
        let lower = status.to_ascii_lowercase();
        if lower == "valid" {
            valid += 1;
            out.push(format!("[서명] Valid: {} | {}", compact(&path.to_string_lossy(), 85), compact(&signer, 80)));
        } else if lower == "notsigned" || lower == "unknownerror" {
            unsigned += 1;
            out.push(format!("[확인] {}: {} | {}", status, compact(&path.to_string_lossy(), 100), compact(&signer, 65)));
        } else {
            warning += 1;
            out.push(format!("[주의] 서명 상태 {}: {} | {}", status, compact(&path.to_string_lossy(), 95), compact(&signer, 65)));
        }
    }

    out.push(format!("[정보] 전자서명 {}개 조회 / Valid {} / 미서명·불명 {} / 경고 {}", checked, valid, unsigned, warning));
}

fn collect_suspicious_file_candidates(rules: &Rules) -> Vec<PathBuf> {
    let mut set = BTreeSet::new();
    const QUERIES: &[(&str, &[&str])] = &[
        ("reg.exe", &["query", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"]),
        ("reg.exe", &["query", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"]),
        ("reg.exe", &["query", "HKLM\\SYSTEM\\CurrentControlSet\\Services", "/s", "/v", "ImagePath"]),
        ("reg.exe", &["query", "HKLM\\SYSTEM\\CurrentControlSet\\Services", "/s", "/v", "ServiceDll"]),
    ];

    for &(program, args) in QUERIES {
        let text = hidden_output(program, args);
        for line in text.lines().map(str::trim) {
            if !(line.contains("REG_SZ") || line.contains("REG_EXPAND_SZ")) { continue; }
            let Some(value) = registry_tail(line) else { continue; };
            if !rules.autorun_is_suspicious(value) { continue; }
            if let Some(path) = extract_existing_path(value) {
                set.insert(path);
            }
        }
    }
    set.into_iter().collect()
}

fn extract_existing_path(command: &str) -> Option<PathBuf> {
    let expanded = expand_env_vars(command.trim());
    let stripped = expanded.trim();
    let first = if let Some(rest) = stripped.strip_prefix('"') {
        let end = rest.find('"')?;
        &rest[..end]
    } else {
        stripped.split_whitespace().next()?
    };

    let path = normalize_nt_prefix(PathBuf::from(first.trim_matches('"')));
    if path.is_file() {
        return Some(path);
    }

    // Some service ImagePath values use an unquoted executable path with spaces.
    let lower = stripped.to_ascii_lowercase();
    for ext in [".exe", ".dll", ".sys", ".scr"] {
        if let Some(pos) = lower.find(ext) {
            let end = pos + ext.len();
            let candidate = normalize_nt_prefix(PathBuf::from(stripped[..end].trim_matches('"')));
            if candidate.is_file() { return Some(candidate); }
        }
    }
    None
}

fn normalize_nt_prefix(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix("\\??\\") {
        PathBuf::from(rest)
    } else {
        path
    }
}

fn expand_env_vars(text: &str) -> String {
    let mut result = text.to_string();
    for (key, value) in env::vars() {
        let token = format!("%{}%", key);
        result = replace_case_insensitive_all(&result, &token, &value);
    }
    result
}

fn replace_case_insensitive_all(source: &str, needle: &str, replacement: &str) -> String {
    if needle.is_empty() { return source.to_string(); }
    let mut result = source.to_string();
    loop {
        let lower = result.to_ascii_lowercase();
        let needle_lower = needle.to_ascii_lowercase();
        let Some(pos) = lower.find(&needle_lower) else { break; };
        result.replace_range(pos..pos + needle.len(), replacement);
    }
    result
}

fn authenticode(path: &Path) -> Option<(String, String)> {
    let escaped = path.to_string_lossy().replace('\'', "''");
    let script = format!(
        "$s=Get-AuthenticodeSignature -LiteralPath '{}'; $sub=if($s.SignerCertificate){{$s.SignerCertificate.Subject}}else{{''}}; Write-Output ($s.Status.ToString()+'|'+$sub)",
        escaped
    );
    let text = hidden_output("powershell.exe", &[
        "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", &script,
    ]);
    let line = text.lines().map(str::trim).find(|l| l.contains('|'))?;
    let (status, signer) = line.split_once('|')?;
    Some((status.trim().to_string(), signer.trim().to_string()))
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

fn compact(text: &str, max_chars: usize) -> String {
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max_chars { return flat; }
    let mut s: String = flat.chars().take(max_chars.saturating_sub(3)).collect();
    s.push_str("...");
    s
}
