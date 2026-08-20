use std::env;
use std::ffi::c_void;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread;
use std::time::Duration;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const WAIT_TIMEOUT: u32 = 258;
const LATEST_RELEASE_API: &str = "https://api.github.com/repos/cys123431-ship-it/QuietGuard/releases/latest";
const RELEASE_ROOT: &str = "https://github.com/cys123431-ship-it/QuietGuard/releases";
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

type HANDLE = *mut c_void;

#[link(name = "kernel32")]
extern "system" {
    fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: i32, dwProcessId: u32) -> HANDLE;
    fn WaitForSingleObject(hHandle: HANDLE, dwMilliseconds: u32) -> u32;
    fn CloseHandle(hObject: HANDLE) -> i32;
}

pub fn update_silent() {
    let lines = check_and_schedule_update();
    write_update_log(&lines);
}

pub fn check_and_schedule_update() -> Vec<String> {
    let mut out = Vec::with_capacity(16);
    out.push(format!("QuietGuard 프로그램 자동 업데이트 확인 (현재 {})", APP_VERSION));

    let dir = update_dir();
    if let Err(e) = fs::create_dir_all(&dir) {
        out.push(format!("[오류] 업데이트 작업 폴더 생성 실패: {}", e));
        return out;
    }

    let latest_json = dir.join("latest.json");
    let _ = fs::remove_file(&latest_json);
    if let Err(e) = download(LATEST_RELEASE_API, &latest_json, true) {
        out.push(format!("[정보] GitHub 최신 릴리즈 확인 실패: {}", e));
        return out;
    }

    let text = match fs::read_to_string(&latest_json) {
        Ok(v) => v,
        Err(e) => {
            out.push(format!("[오류] 최신 릴리즈 정보 읽기 실패: {}", e));
            return out;
        }
    };
    let _ = fs::remove_file(&latest_json);

    let Some(tag) = json_string(&text, "tag_name") else {
        out.push("[정보] GitHub 최신 릴리즈에서 tag_name을 찾지 못했습니다.".into());
        return out;
    };
    let Some(remote_version) = version_from_tag(&tag) else {
        out.push(format!("[차단] 예상하지 못한 릴리즈 태그 형식: {}", tag));
        return out;
    };

    if !version_lt(APP_VERSION, &remote_version) {
        out.push(format!("[최신] QuietGuard {} - 새 프로그램 버전이 없습니다.", APP_VERSION));
        return out;
    }

    let asset_name = format!("QuietGuard-{}-windows-x64.zip", tag);
    let zip_url = format!("{}/download/{}/{}", RELEASE_ROOT, tag, asset_name);
    let sha_url = format!("{}.sha256", zip_url);
    let zip_path = dir.join(&asset_name);
    let sha_path = dir.join(format!("{}.sha256", asset_name));
    let stage = dir.join(format!("stage-{}", remote_version));

    let _ = fs::remove_file(&zip_path);
    let _ = fs::remove_file(&sha_path);
    let _ = fs::remove_dir_all(&stage);

    out.push(format!("[정보] 새 버전 {} 발견 - 검증 후 자동 설치 준비", remote_version));
    if let Err(e) = download(&zip_url, &zip_path, false) {
        out.push(format!("[오류] 프로그램 패키지 다운로드 실패: {}", e));
        return out;
    }
    if let Err(e) = download(&sha_url, &sha_path, false) {
        out.push(format!("[오류] SHA-256 파일 다운로드 실패: {}", e));
        return out;
    }

    let expected = match fs::read_to_string(&sha_path).ok().and_then(|s| parse_sha256(&s)) {
        Some(v) => v,
        None => {
            out.push("[차단] 릴리즈 SHA-256 파일 형식이 올바르지 않습니다.".into());
            return out;
        }
    };
    let actual = match sha256_file(&zip_path) {
        Ok(v) => v,
        Err(e) => {
            out.push(format!("[오류] 다운로드 패키지 SHA-256 계산 실패: {}", e));
            return out;
        }
    };
    if actual != expected {
        out.push("[차단] 다운로드 패키지의 SHA-256이 릴리즈 값과 일치하지 않습니다.".into());
        out.push(format!("예상: {}", expected));
        out.push(format!("실제: {}", actual));
        return out;
    }
    out.push("[검증] 릴리즈 ZIP SHA-256 일치".into());

    if let Err(e) = expand_zip(&zip_path, &stage) {
        out.push(format!("[오류] 업데이트 패키지 압축 해제 실패: {}", e));
        return out;
    }
    let staged_exe = stage.join("QuietGuard.exe");
    if !staged_exe.is_file() {
        out.push("[차단] 릴리즈 패키지에 QuietGuard.exe가 없습니다.".into());
        return out;
    }
    if !stage.join("rules").join("heuristics.conf").is_file() || !stage.join("rules").join("version.json").is_file() {
        out.push("[차단] 릴리즈 패키지의 rules 파일이 완전하지 않습니다.".into());
        return out;
    }

    let target = match env::current_exe() {
        Ok(v) => v,
        Err(e) => {
            out.push(format!("[오류] 현재 QuietGuard 실행 경로 확인 실패: {}", e));
            return out;
        }
    };

    let watcher_was_running = crate::monitor::is_running();
    if watcher_was_running {
        let _ = crate::monitor::request_stop();
        for _ in 0..20 {
            if !crate::monitor::is_running() { break; }
            thread::sleep(Duration::from_millis(250));
        }
    }

    let parent_pid = std::process::id().to_string();
    let watcher_flag = if watcher_was_running { "1" } else { "0" };
    let target_text = target.to_string_lossy().to_string();
    let mut helper = Command::new(&staged_exe);
    helper.args(["--apply-update", &target_text, &parent_pid, watcher_flag, &remote_version]);
    helper.creation_flags(CREATE_NO_WINDOW);
    match helper.spawn() {
        Ok(_) => {
            out.push(format!("[완료] QuietGuard {} 설치 helper를 예약했습니다.", remote_version));
            out.push("현재 자동업데이트 프로세스가 종료된 뒤 실행파일을 교체합니다.".into());
            if watcher_was_running {
                out.push("실시간 감시는 업데이트 후 자동으로 다시 시작됩니다.".into());
            }
        }
        Err(e) => {
            if watcher_was_running { let _ = crate::monitor::start_background(); }
            out.push(format!("[오류] 업데이트 helper 실행 실패: {}", e));
        }
    }
    out
}

pub fn apply_update(args: &[String]) {
    if args.len() < 6 {
        write_update_log(&["[오류] 업데이트 helper 인수가 부족합니다.".into()]);
        return;
    }
    let target = PathBuf::from(&args[2]);
    let parent_pid = args[3].parse::<u32>().unwrap_or(0);
    let restart_watcher = args[4] == "1";
    let version = args[5].clone();

    if parent_pid != 0 { wait_for_process(parent_pid, 60_000); }
    thread::sleep(Duration::from_millis(300));

    let staged_exe = match env::current_exe() {
        Ok(v) => v,
        Err(e) => {
            write_update_log(&[format!("[오류] helper 실행파일 경로 확인 실패: {}", e)]);
            return;
        }
    };
    let stage_dir = staged_exe.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
    let mut lines = vec![format!("QuietGuard {} 자동 설치 적용", version)];

    let success = replace_installed_exe(&staged_exe, &target, &mut lines);
    if success {
        copy_packaged_rules(&stage_dir, &target, &mut lines);
        let _ = fs::write(update_dir().join("installed-version.txt"), format!("{}\n", version));
        lines.push(format!("[완료] QuietGuard {} 프로그램 파일 교체 완료", version));
    } else {
        lines.push("[정보] 다른 QuietGuard 창이 실행 중이면 파일이 잠겨 업데이트가 미뤄질 수 있습니다.".into());
        lines.push("다음 자동 업데이트 확인 때 다시 시도합니다.".into());
    }

    if restart_watcher {
        let mut cmd = Command::new(&target);
        cmd.arg("--watch");
        cmd.creation_flags(CREATE_NO_WINDOW);
        match cmd.spawn() {
            Ok(_) => lines.push("[완료] 실시간 감시를 다시 시작했습니다.".into()),
            Err(e) => lines.push(format!("[정보] 실시간 감시 재시작 실패: {}", e)),
        }
    }
    write_update_log(&lines);
}

fn replace_installed_exe(staged_exe: &Path, target: &Path, lines: &mut Vec<String>) -> bool {
    let new_path = target.with_extension("exe.new");
    let backup = target.with_extension("exe.previous");

    for attempt in 1..=30 {
        let _ = fs::remove_file(&new_path);
        if let Err(e) = fs::copy(staged_exe, &new_path) {
            lines.push(format!("[오류] 새 실행파일 준비 실패: {}", e));
            return false;
        }
        if backup.exists() { let _ = fs::remove_file(&backup); }

        let had_target = target.exists();
        if had_target {
            if fs::rename(target, &backup).is_err() {
                let _ = fs::remove_file(&new_path);
                if attempt < 30 {
                    thread::sleep(Duration::from_secs(1));
                    continue;
                }
                lines.push("[오류] 기존 QuietGuard.exe가 사용 중이라 교체하지 못했습니다.".into());
                return false;
            }
        }

        match fs::rename(&new_path, target) {
            Ok(()) => return true,
            Err(e) => {
                if had_target && backup.exists() && !target.exists() { let _ = fs::rename(&backup, target); }
                let _ = fs::remove_file(&new_path);
                if attempt < 30 {
                    thread::sleep(Duration::from_secs(1));
                    continue;
                }
                lines.push(format!("[오류] 새 QuietGuard.exe 적용 실패: {}", e));
                return false;
            }
        }
    }
    false
}

fn copy_packaged_rules(stage_dir: &Path, target_exe: &Path, lines: &mut Vec<String>) {
    let Some(target_dir) = target_exe.parent() else { return; };
    let source_rules = stage_dir.join("rules");
    let target_rules = target_dir.join("rules");
    if fs::create_dir_all(&target_rules).is_err() { return; }
    for name in ["heuristics.conf", "version.json"] {
        let source = source_rules.join(name);
        let target = target_rules.join(name);
        if source.is_file() {
            if let Err(e) = fs::copy(&source, &target) {
                lines.push(format!("[정보] 동봉 rules/{} 교체 실패: {}", name, e));
            }
        }
    }
}

fn wait_for_process(pid: u32, timeout_ms: u32) {
    unsafe {
        let handle = OpenProcess(SYNCHRONIZE, 0, pid);
        if handle.is_null() { return; }
        let result = WaitForSingleObject(handle, timeout_ms);
        CloseHandle(handle);
        if result == WAIT_TIMEOUT { thread::sleep(Duration::from_millis(250)); }
    }
}

fn expand_zip(zip: &Path, destination: &Path) -> Result<(), String> {
    fs::create_dir_all(destination).map_err(|e| e.to_string())?;
    let zip_ps = ps_quote(&zip.to_string_lossy());
    let dest_ps = ps_quote(&destination.to_string_lossy());
    let script = format!(
        "$ErrorActionPreference='Stop';Expand-Archive -LiteralPath '{}' -DestinationPath '{}' -Force;",
        zip_ps, dest_ps
    );
    let output = hidden_output("powershell.exe", &[
        "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &script,
    ]).map_err(|e| e.to_string())?;
    if output.status.success() { Ok(()) }
    else { Err(compact(&String::from_utf8_lossy(&output.stderr), 220)) }
}

fn download(url: &str, destination: &Path, api: bool) -> Result<(), String> {
    let dest = destination.to_string_lossy().to_string();
    let mut args = vec![
        "--fail", "--silent", "--show-error", "--location",
        "--proto", "=https", "--tlsv1.2", "--connect-timeout", "10", "--max-time", "90",
        "--header", "User-Agent: QuietGuard-self-update",
    ];
    if api { args.extend(["--header", "Accept: application/vnd.github+json"]); }
    args.extend(["--output", &dest, url]);
    if let Ok(output) = hidden_output("curl.exe", &args) {
        if output.status.success() && destination.is_file() { return Ok(()); }
    }

    let safe_url = ps_quote(url);
    let safe_dest = ps_quote(&dest);
    let headers = if api { "-Headers @{'User-Agent'='QuietGuard-self-update';'Accept'='application/vnd.github+json'}" }
        else { "-Headers @{'User-Agent'='QuietGuard-self-update'}" };
    let script = format!(
        "$ProgressPreference='SilentlyContinue';Invoke-WebRequest -UseBasicParsing -TimeoutSec 90 {} -Uri '{}' -OutFile '{}'",
        headers, safe_url, safe_dest
    );
    let output = hidden_output("powershell.exe", &[
        "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &script,
    ]).map_err(|e| format!("curl/PowerShell 실행 실패: {}", e))?;
    if output.status.success() && destination.is_file() { Ok(()) }
    else {
        let err = String::from_utf8_lossy(&output.stderr);
        Err(if err.trim().is_empty() { "HTTPS 다운로드 실패".into() } else { compact(err.trim(), 220) })
    }
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let p = path.to_string_lossy().to_string();
    let output = hidden_output("certutil.exe", &["-hashfile", &p, "SHA256"]).map_err(|e| e.to_string())?;
    if !output.status.success() { return Err("certutil SHA-256 계산 실패".into()); }
    let text = decode_output(&output.stdout);
    parse_sha256(&text).ok_or_else(|| "SHA-256 결과 해석 실패".into())
}

fn parse_sha256(text: &str) -> Option<String> {
    for raw in text.lines() {
        let candidate: String = raw.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if candidate.len() == 64 { return Some(candidate.to_ascii_lowercase()); }
    }
    None
}

fn json_string(text: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\"", key);
    let rest = &text[text.find(&needle)? + needle.len()..];
    let after = rest[rest.find(':')? + 1..].trim_start().strip_prefix('"')?;
    let mut escaped = false;
    for (i, c) in after.char_indices() {
        if escaped { escaped = false; continue; }
        if c == '\\' { escaped = true; continue; }
        if c == '"' { return Some(after[..i].replace("\\/", "/").replace("\\\"", "\"")); }
    }
    None
}

fn version_from_tag(tag: &str) -> Option<String> {
    let version = tag.strip_prefix('v')?;
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|p| p.is_empty() || !p.chars().all(|c| c.is_ascii_digit())) { return None; }
    Some(version.to_string())
}

fn version_lt(current: &str, remote: &str) -> bool { version_tuple(current) < version_tuple(remote) }

fn version_tuple(text: &str) -> (u64, u64, u64) {
    let mut p = text.trim_start_matches('v').split('.').map(|x| x.parse::<u64>().unwrap_or(0));
    (p.next().unwrap_or(0), p.next().unwrap_or(0), p.next().unwrap_or(0))
}

fn update_dir() -> PathBuf {
    if let Ok(local) = env::var("LOCALAPPDATA") { return PathBuf::from(local).join("QuietGuard").join("app-update"); }
    PathBuf::from("QuietGuardData").join("app-update")
}

fn write_update_log(lines: &[String]) {
    let dir = update_dir().parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("QuietGuardData"));
    let _ = fs::create_dir_all(&dir);
    let path = dir.join("app-update.log");
    if let Ok(mut file) = OpenOptions::new().create(true).write(true).truncate(true).open(path) {
        for line in lines { let _ = writeln!(file, "{}", line); }
    }
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
    String::from_utf8_lossy(bytes).into_owned()
}

fn ps_quote(text: &str) -> String { text.replace('\'', "''") }
fn compact(text: &str, max: usize) -> String {
    let flat = text.replace(['\r', '\n'], " ");
    if flat.chars().count() <= max { flat } else { flat.chars().take(max).collect::<String>() + "..." }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_release_tag() {
        assert_eq!(version_from_tag("v1.6.0").as_deref(), Some("1.6.0"));
        assert!(version_from_tag("1.6.0").is_none());
        assert!(version_from_tag("v1.6").is_none());
    }

    #[test]
    fn compares_versions_numerically() {
        assert!(version_lt("1.9.9", "1.10.0"));
        assert!(!version_lt("2.0.0", "1.99.99"));
    }

    #[test]
    fn parses_sha256_line() {
        let hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(parse_sha256(hash).as_deref(), Some(hash));
    }
}
