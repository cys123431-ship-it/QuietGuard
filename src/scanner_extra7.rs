use crate::rules::Rules;
use std::os::windows::process::CommandExt;
use std::process::{Command, Output};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub fn run_extra_scan7() -> Vec<String> {
    let rules = Rules::load();
    let mut out = Vec::with_capacity(80);
    out.push("--- 네트워크·정책·실행제어 추가 점검 ---".into());

    scan_proxy_pac(&mut out, &rules);
    scan_winhttp_proxy(&mut out);
    scan_firewall_rules(&mut out, &rules);
    scan_policy_autoruns(&mut out, &rules);
    scan_execution_restrictions(&mut out, &rules);
    scan_safer_policy(&mut out, &rules);
    scan_safeboot_overrides(&mut out, &rules);
    scan_mozilla_plugins(&mut out, &rules);
    scan_ie_search_and_storage(&mut out, &rules);
    scan_ipsec_policy(&mut out, &rules);
    scan_appcert_dlls(&mut out, &rules);

    out
}

fn scan_proxy_pac(out: &mut Vec<String>, rules: &Rules) {
    let key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
    let text = reg_query(key, false);
    let mut found = 0usize;
    for line in text.lines().map(str::trim) {
        let lower = line.to_ascii_lowercase();
        if !(lower.contains("autoconfigurl") || lower.contains("proxyserver") || lower.contains("proxyoverride") || lower.contains("autodetect")) {
            continue;
        }
        found += 1;
        if rules.autorun_is_suspicious(line)
            || lower.contains("file://")
            || lower.contains("javascript:")
            || lower.contains("vbscript:")
        {
            out.push(format!("[주의] 인터넷 프록시/PAC 설정: {}", compact(line, 150)));
        } else if lower.contains("autoconfigurl") || lower.contains("proxyserver") {
            out.push(format!("[확인] 인터넷 프록시/PAC 설정: {}", compact(line, 150)));
        }
    }
    if found == 0 {
        out.push("[정보] 추가 Proxy/PAC 사용자 설정 없음".into());
    }
}

fn scan_winhttp_proxy(out: &mut Vec<String>) {
    let text = command_output("netsh.exe", &["winhttp", "show", "proxy"]);
    if text.trim().is_empty() {
        out.push("[정보] WinHTTP 프록시 상태를 읽지 못함".into());
        return;
    }
    let lower = text.to_ascii_lowercase();
    if lower.contains("direct access") || text.contains("직접 액세스") {
        out.push("[정상] WinHTTP 프록시: 직접 연결".into());
    } else {
        let summary = text.lines().map(str::trim).filter(|l| !l.is_empty()).take(4).collect::<Vec<_>>().join(" | ");
        out.push(format!("[확인] WinHTTP 프록시 설정 존재: {}", compact(&summary, 180)));
    }
}

fn scan_firewall_rules(out: &mut Vec<String>, rules: &Rules) {
    const KEYS: &[&str] = &[
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\RestrictedServices\\Configurable\\System",
    ];
    let mut total = 0usize;
    let mut suspicious = 0usize;
    for key in KEYS {
        let text = reg_query(key, false);
        for line in text.lines().map(str::trim) {
            if !line.contains("REG_SZ") { continue; }
            total += 1;
            let lower = line.to_ascii_lowercase();
            if rules.autorun_is_suspicious(line)
                || lower.contains("|app=%temp%")
                || lower.contains("\\downloads\\")
                || lower.contains("\\recycle.bin\\")
            {
                suspicious += 1;
                if suspicious <= 25 {
                    out.push(format!("[주의] 방화벽 규칙의 의심 실행 경로: {}", compact(line, 170)));
                }
            }
        }
    }
    out.push(format!("[정보] Windows 방화벽 규칙 {}개 확인, 의심 경로 {}개", total, suspicious));
}

fn scan_policy_autoruns(out: &mut Vec<String>, rules: &Rules) {
    const KEYS: &[(&str, &str)] = &[
        ("HKCU Explorer Policies Run", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"),
        ("HKLM Explorer Policies Run", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"),
    ];
    let mut total = 0usize;
    for (label, key) in KEYS {
        let text = reg_query(key, false);
        for line in text.lines().map(str::trim) {
            if !(line.contains("REG_SZ") || line.contains("REG_EXPAND_SZ")) { continue; }
            total += 1;
            if rules.autorun_is_suspicious(line) {
                out.push(format!("[주의] 정책 자동실행({}): {}", label, compact(line, 155)));
            } else {
                out.push(format!("[확인] 정책 자동실행({}): {}", label, compact(line, 155)));
            }
        }
    }
    if total == 0 {
        out.push("[정보] Explorer 정책 Run 자동실행 항목 없음".into());
    }
}

fn scan_execution_restrictions(out: &mut Vec<String>, rules: &Rules) {
    const KEYS: &[(&str, &str)] = &[
        ("HKCU DisallowRun", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun"),
        ("HKLM DisallowRun", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun"),
        ("HKCU RestrictRun", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\RestrictRun"),
        ("HKLM RestrictRun", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\RestrictRun"),
    ];
    for (label, key) in KEYS {
        let text = reg_query(key, false);
        let values: Vec<&str> = text.lines().map(str::trim).filter(|l| l.contains("REG_SZ")).collect();
        if values.is_empty() { continue; }
        out.push(format!("[확인] {} 정책 값 {}개", label, values.len()));
        for line in values.into_iter().filter(|l| rules.autorun_is_suspicious(l)).take(6) {
            out.push(format!("[주의] 실행 제한 정책 의심 항목: {}", compact(line, 150)));
        }
    }
}

fn scan_safer_policy(out: &mut Vec<String>, rules: &Rules) {
    const KEYS: &[&str] = &[
        "HKLM\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers",
        "HKCU\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers",
    ];
    let mut present = 0usize;
    let mut suspicious = 0usize;
    for key in KEYS {
        let text = reg_query(key, true);
        if text.trim().is_empty() { continue; }
        present += 1;
        for line in text.lines().map(str::trim) {
            if rules.autorun_is_suspicious(line) {
                suspicious += 1;
                if suspicious <= 20 {
                    out.push(format!("[주의] Software Restriction Policy 의심 경로: {}", compact(line, 160)));
                }
            }
        }
    }
    if present > 0 {
        out.push(format!("[정보] Software Restriction Policy 영역 {}개 존재, 의심 문자열 {}개", present, suspicious));
    }
}

fn scan_safeboot_overrides(out: &mut Vec<String>, rules: &Rules) {
    let text = reg_query("HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot", true);
    if text.trim().is_empty() { return; }
    let mut suspicious = 0usize;
    for line in text.lines().map(str::trim) {
        if rules.autorun_is_suspicious(line) {
            suspicious += 1;
            if suspicious <= 20 {
                out.push(format!("[주의] SafeBoot 영역 의심 문자열: {}", compact(line, 160)));
            }
        }
    }
    if suspicious == 0 {
        out.push("[정보] SafeBoot 설정에서 일반 휴리스틱 의심 문자열 없음".into());
    }
}

fn scan_mozilla_plugins(out: &mut Vec<String>, rules: &Rules) {
    const KEYS: &[&str] = &[
        "HKCU\\Software\\MozillaPlugins",
        "HKLM\\Software\\MozillaPlugins",
        "HKLM\\Software\\WOW6432Node\\MozillaPlugins",
    ];
    let mut total = 0usize;
    let mut suspicious = 0usize;
    for key in KEYS {
        let text = reg_query(key, true);
        for line in text.lines().map(str::trim) {
            if !(line.contains("REG_SZ") || line.contains("REG_EXPAND_SZ")) { continue; }
            total += 1;
            if rules.autorun_is_suspicious(line) {
                suspicious += 1;
                if suspicious <= 20 {
                    out.push(format!("[주의] Mozilla 플러그인 의심 경로: {}", compact(line, 160)));
                }
            }
        }
    }
    if total > 0 {
        out.push(format!("[정보] MozillaPlugins 값 {}개 확인, 의심 경로 {}개", total, suspicious));
    }
}

fn scan_ie_search_and_storage(out: &mut Vec<String>, rules: &Rules) {
    let search = reg_query("HKCU\\Software\\Microsoft\\Internet Explorer\\SearchScopes", true);
    let mut urls = 0usize;
    let mut suspicious = 0usize;
    for line in search.lines().map(str::trim) {
        let lower = line.to_ascii_lowercase();
        if !(lower.contains(" url ") || lower.contains("suggesturl") || lower.contains("topresulturl")) { continue; }
        if !line.contains("REG_SZ") { continue; }
        urls += 1;
        if rules.autorun_is_suspicious(line)
            || lower.contains("javascript:")
            || lower.contains("file://")
            || lower.contains("127.0.0.1")
        {
            suspicious += 1;
            out.push(format!("[주의] IE 검색 공급자 의심 URL: {}", compact(line, 160)));
        }
    }
    if urls > 0 {
        out.push(format!("[정보] IE SearchScopes URL {}개 확인, 의심 {}개", urls, suspicious));
    }

    let storage = reg_query("HKCU\\Software\\Microsoft\\Internet Explorer\\DOMStorage", false);
    let origins = storage.lines().map(str::trim).filter(|l| l.starts_with("HKEY_")).count().saturating_sub(1);
    if origins > 0 {
        out.push(format!("[정보] IE DOMStorage 등록 원본 약 {}개", origins));
    }
}

fn scan_ipsec_policy(out: &mut Vec<String>, rules: &Rules) {
    let key = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\IPSec\\Policy\\Local";
    let text = reg_query(key, true);
    if text.trim().is_empty() { return; }
    let suspicious: Vec<&str> = text.lines().map(str::trim)
        .filter(|l| rules.autorun_is_suspicious(l))
        .take(8)
        .collect();
    if suspicious.is_empty() {
        out.push("[정보] 로컬 IPsec 정책 영역 존재(관리 환경에서는 정상일 수 있음)".into());
    } else {
        out.push(format!("[주의] 로컬 IPsec 정책에서 의심 경로/명령 {}개", suspicious.len()));
        for line in suspicious { out.push(format!("  - {}", compact(line, 150))); }
    }
}

fn scan_appcert_dlls(out: &mut Vec<String>, rules: &Rules) {
    let key = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls";
    let text = reg_query(key, false);
    let values: Vec<&str> = text.lines().map(str::trim)
        .filter(|l| l.contains("REG_SZ") || l.contains("REG_EXPAND_SZ"))
        .collect();
    if values.is_empty() { return; }
    out.push(format!("[확인] AppCertDlls 값 {}개", values.len()));
    for line in values.into_iter().take(15) {
        if rules.autorun_is_suspicious(line) {
            out.push(format!("[주의] AppCertDlls 의심 경로: {}", compact(line, 160)));
        } else {
            out.push(format!("[확인] AppCertDlls: {}", compact(line, 160)));
        }
    }
}

fn reg_query(key: &str, recursive: bool) -> String {
    let mut args = vec!["query", key];
    if recursive { args.push("/s"); }
    command_output("reg.exe", &args)
}

fn command_output(program: &str, args: &[&str]) -> String {
    match hidden_output(program, args) {
        Ok(o) => decode_output(o),
        Err(_) => String::new(),
    }
}

fn hidden_output(program: &str, args: &[&str]) -> std::io::Result<Output> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.output()
}

fn decode_output(output: Output) -> String {
    let bytes = output.stdout;
    if bytes.starts_with(&[0xFF, 0xFE]) {
        let values: Vec<u16> = bytes[2..].chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        return String::from_utf16_lossy(&values);
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        let values: Vec<u16> = bytes[2..].chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
        return String::from_utf16_lossy(&values);
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn compact(text: &str, max_chars: usize) -> String {
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max_chars { return flat; }
    let mut s: String = flat.chars().take(max_chars.saturating_sub(3)).collect();
    s.push_str("...");
    s
}
