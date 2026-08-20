use crate::rules::Rules;
use std::os::windows::process::CommandExt;
use std::process::Command;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub fn run_extra_scan2() -> Vec<String> {
    let rules = Rules::load();
    let mut out = Vec::with_capacity(32);
    out.push("--- 추가 자동실행/브라우저 변조 점검 ---".to_string());
    scan_environment_and_logon(&mut out, &rules);
    scan_file_associations(&mut out, &rules);
    scan_uninstall_entries(&mut out, &rules);
    scan_browser_shortcuts(&mut out, &rules);
    scan_ie_elevation_policy(&mut out, &rules);
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

fn scan_environment_and_logon(out: &mut Vec<String>, rules: &Rules) {
    let user_env = command_output("reg", &["query", "HKCU\\Environment"]);
    let machine_env = command_output("reg", &["query", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"]);
    let mut suspicious = 0usize;
    for (scope, text) in [("사용자", user_env.as_str()), ("시스템", machine_env.as_str())] {
        for line in text.lines().map(str::trim) {
            if !(line.contains("REG_SZ") || line.contains("REG_EXPAND_SZ")) { continue; }
            if rules.path_is_suspicious(line) || rules.command_is_suspicious(line) {
                suspicious += 1;
                if suspicious <= 8 { out.push(format!("[주의] {} 환경변수: {}", scope, compact(line, 120))); }
            }
        }
    }

    let logon = command_output("reg", &["query", "HKCU\\Environment", "/v", "UserInitMprLogonScript"]);
    if let Some(line) = logon.lines().map(str::trim).find(|l| l.to_ascii_lowercase().contains("userinitmprlogonscript")) {
        if line.contains("REG_SZ") || line.contains("REG_EXPAND_SZ") {
            if rules.autorun_is_suspicious(line) { out.push(format!("[주의] UserInitMprLogonScript: {}", compact(line, 120))); }
            else { out.push(format!("[확인] UserInitMprLogonScript 등록: {}", compact(line, 120))); }
        }
    }

    let startup = command_output("reg", &["query", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders", "/v", "Startup"]);
    if let Some(line) = startup.lines().map(str::trim).find(|l| l.to_ascii_lowercase().contains("startup")) {
        if rules.path_is_suspicious(line) { out.push(format!("[주의] Startup 폴더 경로 변경 의심: {}", compact(line, 120))); }
    }
    out.push(format!("[정보] 환경변수/로그온 스크립트 주의 패턴 {}건", suspicious));
}

fn scan_file_associations(out: &mut Vec<String>, rules: &Rules) {
    const CLASSES: &[&str] = &["exefile", "comfile", "batfile", "cmdfile", "mscfile", "htmlfile", "http", "https"];
    let mut overrides = 0usize;
    let mut suspicious = 0usize;
    for &class in CLASSES {
        for root in ["HKCU\\Software\\Classes", "HKLM\\Software\\Classes"] {
            let key = format!("{}\\{}\\shell\\open\\command", root, class);
            let text = command_output("reg", &["query", key.as_str(), "/ve"]);
            if text.is_empty() { continue; }
            for line in text.lines().map(str::trim) {
                if !(line.contains("REG_SZ") || line.contains("REG_EXPAND_SZ")) { continue; }
                overrides += 1;
                if rules.autorun_is_suspicious(line) {
                    suspicious += 1;
                    out.push(format!("[주의] 파일/URL 연결 {}: {}", class, compact(line, 120)));
                }
            }
        }
    }
    out.push(format!("[정보] 파일/URL 연결 명령 {}개 확인, 주의 {}개", overrides, suspicious));
}

fn scan_uninstall_entries(out: &mut Vec<String>, rules: &Rules) {
    const ROOTS: &[&str] = &[
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "HKLM\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
    ];
    let mut strings = 0usize;
    let mut suspicious = 0usize;
    for &root in ROOTS {
        let text = command_output("reg", &["query", root, "/s"]);
        for line in text.lines().map(str::trim) {
            let lower = line.to_ascii_lowercase();
            if !(lower.contains("uninstallstring") || lower.contains("quietuninstallstring")) { continue; }
            if !(line.contains("REG_SZ") || line.contains("REG_EXPAND_SZ")) { continue; }
            strings += 1;
            if rules.autorun_is_suspicious(line) {
                suspicious += 1;
                if suspicious <= 8 { out.push(format!("[주의] 제거 명령 경로: {}", compact(line, 120))); }
            }
        }
    }
    out.push(format!("[정보] 설치 제거 명령 {}개 검사, 주의 {}개", strings, suspicious));
}

fn scan_browser_shortcuts(out: &mut Vec<String>, rules: &Rules) {
    let script = "$ErrorActionPreference='SilentlyContinue'; ".to_string()
        + "$w=New-Object -ComObject WScript.Shell; "
        + "$dirs=@([Environment]::GetFolderPath('Desktop'),[Environment]::GetFolderPath('CommonDesktopDirectory'),[Environment]::GetFolderPath('StartMenu'),[Environment]::GetFolderPath('CommonStartMenu')); "
        + "foreach($d in $dirs){ if(Test-Path $d){ Get-ChildItem $d -Filter *.lnk -Recurse | ForEach-Object { $s=$w.CreateShortcut($_.FullName); if($s.TargetPath -match '(?i)(chrome|msedge|firefox|iexplore)\\.exe$'){ 'LNK|' + $_.FullName + '|' + $s.TargetPath + '|' + $s.Arguments } } } }";
    let text = command_output("powershell.exe", &["-NoProfile", "-NonInteractive", "-Command", script.as_str()]);
    let mut total = 0usize;
    let mut suspicious = 0usize;
    for line in text.lines().map(str::trim).filter(|l| l.starts_with("LNK|")) {
        total += 1;
        let lower = line.to_ascii_lowercase();
        let has_url_arg = lower.contains("|http://") || lower.contains("|https://") || lower.contains(" http://") || lower.contains(" https://");
        if rules.autorun_is_suspicious(line) {
            suspicious += 1;
            if suspicious <= 8 { out.push(format!("[주의] 브라우저 바로가기: {}", compact(line, 120))); }
        } else if has_url_arg {
            out.push(format!("[확인] URL 인수가 붙은 브라우저 바로가기: {}", compact(line, 120)));
        }
    }
    out.push(format!("[정보] 브라우저 바로가기 {}개 확인, 주의 {}개", total, suspicious));
}

fn scan_ie_elevation_policy(out: &mut Vec<String>, rules: &Rules) {
    const ROOTS: &[&str] = &[
        "HKCU\\Software\\Microsoft\\Internet Explorer\\Low Rights\\ElevationPolicy",
        "HKLM\\Software\\Microsoft\\Internet Explorer\\Low Rights\\ElevationPolicy",
    ];
    let mut total = 0usize;
    let mut suspicious = 0usize;
    for &root in ROOTS {
        let text = command_output("reg", &["query", root, "/s"]);
        for line in text.lines().map(str::trim) {
            let lower = line.to_ascii_lowercase();
            if !(lower.contains("appname") || lower.contains("apppath")) { continue; }
            if !(line.contains("REG_SZ") || line.contains("REG_EXPAND_SZ")) { continue; }
            total += 1;
            if rules.path_is_suspicious(line) || rules.command_is_suspicious(line) {
                suspicious += 1;
                if suspicious <= 6 { out.push(format!("[주의] IE ElevationPolicy: {}", compact(line, 120))); }
            }
        }
    }
    out.push(format!("[정보] IE ElevationPolicy 값 {}개 검사, 주의 {}개", total, suspicious));
}

fn compact(text: &str, max_chars: usize) -> String {
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max_chars { return flat; }
    let mut s: String = flat.chars().take(max_chars.saturating_sub(3)).collect();
    s.push_str("...");
    s
}
