use crate::rules::Rules;
use std::process::Command;

pub fn run_extra_scan() -> Vec<String> {
    let rules = Rules::load();
    let mut out = Vec::with_capacity(32);
    out.push("--- 확장 지속성/하이재킹 점검 ---".to_string());
    scan_service_dlls(&mut out, &rules);
    scan_ifeo_debuggers(&mut out, &rules);
    scan_bits_jobs(&mut out, &rules);
    scan_winsock(&mut out, &rules);
    scan_wmi_persistence(&mut out, &rules);
    scan_browser_policies(&mut out);
    out
}

fn command_output(program: &str, args: &[&str]) -> String {
    match Command::new(program).args(args).output() {
        Ok(o) => {
            let bytes = o.stdout;
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
            String::from_utf8_lossy(&bytes).into_owned()
        }
        Err(_) => String::new(),
    }
}

fn scan_service_dlls(out: &mut Vec<String>, rules: &Rules) {
    let text = command_output("reg", &[
        "query", "HKLM\\SYSTEM\\CurrentControlSet\\Services", "/s", "/v", "ServiceDll"
    ]);
    if text.is_empty() {
        out.push("[정보] ServiceDll: 조회 결과 없음".into());
        return;
    }
    let mut total = 0usize;
    let mut suspicious = 0usize;
    for line in text.lines().map(str::trim) {
        if !line.to_ascii_lowercase().contains("servicedll") { continue; }
        if !(line.contains("REG_SZ") || line.contains("REG_EXPAND_SZ")) { continue; }
        total += 1;
        if rules.path_is_suspicious(line) {
            suspicious += 1;
            out.push(format!("[주의] ServiceDll 경로: {}", compact(line, 120)));
        }
    }
    out.push(format!("[정보] ServiceDll {}개 검사, 주의 {}개", total, suspicious));
}

fn scan_ifeo_debuggers(out: &mut Vec<String>, rules: &Rules) {
    let text = command_output("reg", &[
        "query",
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        "/s", "/v", "Debugger"
    ]);
    if text.is_empty() {
        out.push("[정상] IFEO Debugger: 등록 항목 없음".into());
        return;
    }
    let mut total = 0usize;
    let mut suspicious = 0usize;
    for line in text.lines().map(str::trim) {
        let lower = line.to_ascii_lowercase();
        if !lower.contains("debugger") || !(line.contains("REG_SZ") || line.contains("REG_EXPAND_SZ")) {
            continue;
        }
        total += 1;
        if rules.autorun_is_suspicious(line) {
            suspicious += 1;
            out.push(format!("[주의] IFEO Debugger: {}", compact(line, 120)));
        } else {
            out.push(format!("[확인] IFEO Debugger 등록: {}", compact(line, 120)));
        }
    }
    out.push(format!("[정보] IFEO Debugger {}개, 주의 {}개", total, suspicious));
}

fn scan_bits_jobs(out: &mut Vec<String>, rules: &Rules) {
    let text = command_output("bitsadmin", &["/list", "/allusers", "/verbose"]);
    if text.is_empty() {
        out.push("[정보] BITS: 조회 불가 또는 작업 없음".into());
        return;
    }
    let mut suspicious = 0usize;
    for line in text.lines().map(str::trim) {
        if rules.autorun_is_suspicious(line) {
            suspicious += 1;
            if suspicious <= 5 {
                out.push(format!("[주의] BITS 관련 경로/명령: {}", compact(line, 120)));
            }
        }
    }
    if suspicious == 0 {
        out.push("[정보] BITS: 의심 경로/명령 패턴 없음".into());
    } else {
        out.push(format!("[정보] BITS: 의심 패턴 {}건", suspicious));
    }
}

fn scan_winsock(out: &mut Vec<String>, rules: &Rules) {
    let text = command_output("netsh", &["winsock", "show", "catalog"]);
    if text.is_empty() {
        out.push("[정보] Winsock 카탈로그를 읽지 못함".into());
        return;
    }
    let mut suspicious = 0usize;
    for line in text.lines().map(str::trim) {
        if rules.path_is_suspicious(line) {
            suspicious += 1;
            if suspicious <= 5 {
                out.push(format!("[주의] Winsock 공급자 경로: {}", compact(line, 120)));
            }
        }
    }
    if suspicious == 0 {
        out.push("[정보] Winsock: 사용자 쓰기 경로 기반 공급자 흔적 없음".into());
    } else {
        out.push(format!("[정보] Winsock: 주의 패턴 {}건", suspicious));
    }
}

fn scan_wmi_persistence(out: &mut Vec<String>, rules: &Rules) {
    let script = "$ErrorActionPreference='SilentlyContinue'; "
        .to_string()
        + "$x=@(); "
        + "$x += Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer | ForEach-Object { 'CMD|' + $_.Name + '|' + $_.CommandLineTemplate }; "
        + "$x += Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer | ForEach-Object { 'SCRIPT|' + $_.Name + '|' + $_.ScriptingEngine }; "
        + "$x | ForEach-Object { $_ }";
    let text = command_output("powershell.exe", &[
        "-NoProfile", "-NonInteractive", "-Command", script.as_str()
    ]);
    let entries: Vec<&str> = text.lines()
        .map(str::trim)
        .filter(|l| l.starts_with("CMD|") || l.starts_with("SCRIPT|"))
        .collect();
    if entries.is_empty() {
        out.push("[정보] WMI 영구 소비자: 발견 없음 또는 조회 불가".into());
        return;
    }
    out.push(format!("[확인] WMI 영구 이벤트 소비자 {}개", entries.len()));
    for entry in entries.iter().take(5) {
        if rules.autorun_is_suspicious(entry) {
            out.push(format!("[주의] WMI: {}", compact(entry, 120)));
        } else {
            out.push(format!("  - {}", compact(entry, 120)));
        }
    }
}

fn scan_browser_policies(out: &mut Vec<String>) {
    const TARGETS: &[(&str, &str, &[&str])] = &[
        (
            "Chrome 정책",
            "HKCU\\Software\\Policies\\Google\\Chrome",
            &["HomepageLocation", "DefaultSearchProviderSearchURL", "RestoreOnStartupURLs"],
        ),
        (
            "Edge 정책",
            "HKCU\\Software\\Policies\\Microsoft\\Edge",
            &["HomepageLocation", "DefaultSearchProviderSearchURL", "RestoreOnStartupURLs"],
        ),
        (
            "Chrome 시스템 정책",
            "HKLM\\Software\\Policies\\Google\\Chrome",
            &["HomepageLocation", "DefaultSearchProviderSearchURL", "RestoreOnStartupURLs"],
        ),
        (
            "Edge 시스템 정책",
            "HKLM\\Software\\Policies\\Microsoft\\Edge",
            &["HomepageLocation", "DefaultSearchProviderSearchURL", "RestoreOnStartupURLs"],
        ),
    ];

    let mut found = 0usize;
    for &(label, key, names) in TARGETS {
        let text = command_output("reg", &["query", key]);
        if text.is_empty() { continue; }
        for &name in names {
            let lower_name = name.to_ascii_lowercase();
            for line in text.lines().map(str::trim) {
                if line.to_ascii_lowercase().contains(&lower_name) {
                    found += 1;
                    out.push(format!("[확인] {}: {}", label, compact(line, 120)));
                }
            }
        }
    }

    let ie = command_output("reg", &[
        "query", "HKCU\\Software\\Microsoft\\Internet Explorer\\Main"
    ]);
    for line in ie.lines().map(str::trim) {
        let lower = line.to_ascii_lowercase();
        if lower.contains("start page") || lower.contains("search page") {
            found += 1;
            out.push(format!("[정보] 브라우저 시작/검색 설정: {}", compact(line, 120)));
        }
    }
    if found == 0 {
        out.push("[정보] 브라우저 시작/검색 강제 정책 흔적 없음".into());
    }
}

fn compact(text: &str, max_chars: usize) -> String {
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max_chars { return flat; }
    let mut s: String = flat.chars().take(max_chars.saturating_sub(3)).collect();
    s.push_str("...");
    s
}
