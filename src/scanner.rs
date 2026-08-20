use crate::rules::Rules;
use std::env;
use std::fs;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub fn run_quick_scan() -> Vec<String> {
    let rules = Rules::load();
    let mut out = Vec::with_capacity(64);
    out.push(format!("QuietGuard {} 시스템 점검 시작", env!("CARGO_PKG_VERSION")));

    scan_hosts(&mut out);
    scan_proxy(&mut out);
    scan_dns(&mut out);
    scan_registry_autoruns(&mut out, &rules);
    scan_startup_folders(&mut out, &rules);
    scan_services(&mut out, &rules);
    scan_scheduled_tasks(&mut out, &rules);
    scan_browser_extensions(&mut out);

    out.push("점검 완료 - 현재 버전은 발견 항목을 자동 삭제하지 않습니다.".to_string());
    out
}

fn command_output(program: &str, args: &[&str]) -> String {
    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.creation_flags(CREATE_NO_WINDOW);
    match cmd.output() {
        Ok(o) => {
            let bytes = o.stdout;
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
            String::from_utf8_lossy(&bytes).into_owned()
        }
        Err(_) => String::new(),
    }
}

fn scan_hosts(out: &mut Vec<String>) {
    let windir = env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".to_string());
    let hosts = format!("{}\\System32\\drivers\\etc\\hosts", windir);
    match fs::read_to_string(&hosts) {
        Ok(content) => {
            let entries: Vec<&str> = content.lines().map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .filter(|l| !is_default_hosts_entry(l)).collect();
            if entries.is_empty() {
                out.push("[정상] Hosts: 특이 항목 없음".into());
            } else {
                out.push(format!("[주의] Hosts: 사용자 정의 항목 {}개", entries.len()));
                for item in entries.iter().take(4) { out.push(format!("  - {}", item)); }
            }
        }
        Err(_) => out.push("[정보] Hosts: 파일을 읽지 못함".into()),
    }
}

fn is_default_hosts_entry(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.starts_with("127.0.0.1 localhost") || lower.starts_with("::1 localhost")
}

fn scan_proxy(out: &mut Vec<String>) {
    let base = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
    let enabled = command_output("reg", &["query", base, "/v", "ProxyEnable"]);
    let server = command_output("reg", &["query", base, "/v", "ProxyServer"]);
    if enabled.to_ascii_lowercase().contains("0x1") {
        let server_text = registry_value_tail(&server).unwrap_or("(주소 확인 필요)");
        out.push(format!("[주의] Proxy: 활성화됨 {}", server_text));
    } else {
        out.push("[정상] Proxy: 비활성".into());
    }
}

fn scan_dns(out: &mut Vec<String>) {
    let text = command_output("reg", &["query", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces", "/s", "/v", "NameServer"]);
    let values: Vec<&str> = text.lines().map(str::trim)
        .filter(|l| l.to_ascii_lowercase().contains("nameserver") && !l.ends_with("REG_SZ"))
        .collect();
    if values.is_empty() {
        out.push("[정보] DNS: 명시적 IPv4 DNS 설정 흔적 없음(DHCP 가능)".into());
    } else {
        out.push(format!("[정보] DNS: 명시적으로 설정된 인터페이스 {}개", values.len()));
    }
}

fn scan_registry_autoruns(out: &mut Vec<String>, rules: &Rules) {
    const KEYS: &[(&str, &str)] = &[
        ("HKCU Run", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
        ("HKCU RunOnce", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        ("HKLM Run", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
        ("HKLM RunOnce", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        ("HKLM 32-bit Run", "HKLM\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"),
        ("Command Processor HKCU", "HKCU\\Software\\Microsoft\\Command Processor"),
        ("Command Processor HKLM", "HKLM\\Software\\Microsoft\\Command Processor"),
        ("Winlogon", "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"),
        ("Windows AppInit", "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows"),
    ];

    let mut total = 0usize;
    let mut suspicious = 0usize;
    for &(label, key) in KEYS {
        let text = command_output("reg", &["query", key]);
        if text.is_empty() { continue; }
        for line in text.lines().map(str::trim) {
            if !(line.contains("REG_SZ") || line.contains("REG_EXPAND_SZ") || line.contains("REG_MULTI_SZ")) { continue; }
            let lower = line.to_ascii_lowercase();
            let relevant = if label.contains("Command Processor") {
                lower.contains("autorun")
            } else if label == "Winlogon" {
                lower.contains("shell") || lower.contains("userinit") || lower.contains("notify")
            } else if label == "Windows AppInit" {
                lower.contains("appinit_dlls") || lower.contains("loadappinit_dlls")
            } else { true };
            if !relevant { continue; }
            total += 1;
            if rules.autorun_is_suspicious(line) {
                suspicious += 1;
                out.push(format!("[주의] 자동실행({}): {}", label, compact(line, 120)));
            }
        }
    }
    out.push(format!("[정보] 레지스트리 자동실행/로그온 지점 {}개 검사, 주의 {}개", total, suspicious));
}

fn scan_startup_folders(out: &mut Vec<String>, rules: &Rules) {
    let mut dirs = Vec::new();
    if let Ok(appdata) = env::var("APPDATA") { dirs.push(PathBuf::from(appdata).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup")); }
    if let Ok(programdata) = env::var("ProgramData") { dirs.push(PathBuf::from(programdata).join("Microsoft\\Windows\\Start Menu\\Programs\\StartUp")); }

    let mut total = 0usize;
    let mut suspicious = 0usize;
    for dir in dirs {
        let Ok(read) = fs::read_dir(&dir) else { continue; };
        for entry in read.flatten() {
            total += 1;
            let path = entry.path();
            let text = path.to_string_lossy();
            if rules.autorun_is_suspicious(&text) || has_script_extension(&path, rules) {
                suspicious += 1;
                out.push(format!("[주의] Startup 폴더: {}", compact(&text, 120)));
            }
        }
    }
    out.push(format!("[정보] Startup 폴더 항목 {}개, 주의 {}개", total, suspicious));
}

fn scan_services(out: &mut Vec<String>, rules: &Rules) {
    let text = command_output("reg", &["query", "HKLM\\SYSTEM\\CurrentControlSet\\Services", "/s", "/v", "ImagePath"]);
    if text.is_empty() { out.push("[정보] 서비스 ImagePath를 읽지 못함".into()); return; }
    let mut total = 0usize;
    let mut suspicious = 0usize;
    for line in text.lines().map(str::trim) {
        if !line.to_ascii_lowercase().contains("imagepath") { continue; }
        if !(line.contains("REG_SZ") || line.contains("REG_EXPAND_SZ")) { continue; }
        total += 1;
        if rules.autorun_is_suspicious(line) {
            suspicious += 1;
            out.push(format!("[주의] 서비스 실행 경로: {}", compact(line, 120)));
        }
    }
    out.push(format!("[정보] 서비스 ImagePath {}개 검사, 주의 {}개", total, suspicious));
}

fn scan_scheduled_tasks(out: &mut Vec<String>, rules: &Rules) {
    let text = command_output("schtasks", &["/query", "/fo", "csv", "/v"]);
    if text.is_empty() { out.push("[정보] 예약 작업 목록을 읽지 못함".into()); return; }
    let mut total = 0usize;
    let mut suspicious = 0usize;
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || !t.starts_with('"') { continue; }
        total += 1;
        if rules.autorun_is_suspicious(t) {
            suspicious += 1;
            out.push(format!("[주의] 예약 작업: {}", compact(t, 120)));
        }
    }
    total = total.saturating_sub(1);
    out.push(format!("[정보] 예약 작업 약 {}개 검사, 주의 {}개", total, suspicious));
}

fn scan_browser_extensions(out: &mut Vec<String>) {
    let mut chrome = 0usize;
    let mut edge = 0usize;
    let mut firefox = 0usize;
    if let Ok(local) = env::var("LOCALAPPDATA") {
        let local = PathBuf::from(local);
        chrome = count_chromium_extensions(&local.join("Google\\Chrome\\User Data"));
        edge = count_chromium_extensions(&local.join("Microsoft\\Edge\\User Data"));
    }
    if let Ok(roaming) = env::var("APPDATA") {
        firefox = count_firefox_extensions(&PathBuf::from(roaming).join("Mozilla\\Firefox\\Profiles"));
    }
    out.push(format!("[정보] 브라우저 확장: Chrome {} / Edge {} / Firefox {}", chrome, edge, firefox));

    let policy_keys = [
        ("Chrome", "HKCU\\Software\\Policies\\Google\\Chrome\\ExtensionInstallForcelist"),
        ("Chrome(시스템)", "HKLM\\Software\\Policies\\Google\\Chrome\\ExtensionInstallForcelist"),
        ("Edge", "HKCU\\Software\\Policies\\Microsoft\\Edge\\ExtensionInstallForcelist"),
        ("Edge(시스템)", "HKLM\\Software\\Policies\\Microsoft\\Edge\\ExtensionInstallForcelist"),
    ];
    for (label, key) in policy_keys {
        let text = command_output("reg", &["query", key]);
        let count = text.lines().filter(|l| l.contains("REG_SZ")).count();
        if count > 0 { out.push(format!("[확인] {} 강제 설치 확장 정책 {}개", label, count)); }
    }
}

fn count_chromium_extensions(user_data: &Path) -> usize {
    let Ok(profiles) = fs::read_dir(user_data) else { return 0; };
    let mut count = 0usize;
    for p in profiles.flatten() {
        let name = p.file_name().to_string_lossy().to_string();
        if name != "Default" && !name.starts_with("Profile ") { continue; }
        let ext_dir = p.path().join("Extensions");
        let Ok(exts) = fs::read_dir(ext_dir) else { continue; };
        count += exts.flatten().filter(|e| e.path().is_dir()).count();
    }
    count
}

fn count_firefox_extensions(profiles: &Path) -> usize {
    let Ok(items) = fs::read_dir(profiles) else { return 0; };
    let mut count = 0usize;
    for p in items.flatten() {
        let ext = p.path().join("extensions");
        let Ok(exts) = fs::read_dir(ext) else { continue; };
        count += exts.flatten().count();
    }
    count
}

fn has_script_extension(path: &Path, rules: &Rules) -> bool {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    rules.script_extensions.iter().any(|ext| lower.ends_with(ext))
}

fn registry_value_tail(text: &str) -> Option<&str> {
    text.lines().map(str::trim)
        .find(|l| l.contains("REG_SZ") || l.contains("REG_EXPAND_SZ"))
        .and_then(|l| {
            if let Some((_, tail)) = l.split_once("REG_EXPAND_SZ") { Some(tail.trim()) }
            else if let Some((_, tail)) = l.split_once("REG_SZ") { Some(tail.trim()) }
            else { None }
        })
}

fn compact(text: &str, max_chars: usize) -> String {
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max_chars { return flat; }
    let mut s: String = flat.chars().take(max_chars.saturating_sub(3)).collect();
    s.push_str("...");
    s
}
