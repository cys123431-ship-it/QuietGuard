use std::env;
use std::os::windows::process::CommandExt;
use std::process::Command;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const RUN_KEY: &str = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
const STARTUP_VALUE: &str = "QuietGuard";
const MONITOR_VALUE: &str = "QuietGuardMonitor";
const DB_TASK: &str = "QuietGuard DB Update";
const APP_TASK: &str = "QuietGuard App Update";
const DB_TASK_HOURS: &str = "6";
const APP_TASK_HOURS: &str = "6";

pub fn toggle_windows_startup() -> Vec<String> {
    if windows_startup_enabled() {
        let result = hidden_status("reg.exe", &["delete", RUN_KEY, "/v", STARTUP_VALUE, "/f"]);
        if result { vec!["[완료] Windows 로그인 시 QuietGuard 자동 실행을 껐습니다.".into()] }
        else { vec!["[오류] Windows 자동 실행 항목을 제거하지 못했습니다.".into()] }
    } else {
        let Some(command) = exe_command("") else { return vec!["[오류] QuietGuard 실행 파일 경로를 확인하지 못했습니다.".into()]; };
        let result = hidden_status("reg.exe", &["add", RUN_KEY, "/v", STARTUP_VALUE, "/t", "REG_SZ", "/d", &command, "/f"]);
        if result { vec!["[완료] Windows 로그인 시 QuietGuard 자동 실행을 켰습니다.".into(), "기존 등록 경로가 달랐다면 현재 실행 파일 경로로 복구했습니다.".into()] }
        else { vec!["[오류] Windows 자동 실행 항목을 등록하지 못했습니다.".into()] }
    }
}

pub fn toggle_monitor_autostart() -> Vec<String> {
    if monitor_autostart_enabled() {
        let result = hidden_status("reg.exe", &["delete", RUN_KEY, "/v", MONITOR_VALUE, "/f"]);
        if result { vec!["[완료] 로그인 시 실시간 감시 자동 시작을 껐습니다.".into()] }
        else { vec!["[오류] 실시간 감시 자동 시작 항목을 제거하지 못했습니다.".into()] }
    } else {
        let Some(command) = exe_command("--watch") else { return vec!["[오류] QuietGuard 실행 파일 경로를 확인하지 못했습니다.".into()]; };
        let result = hidden_status("reg.exe", &["add", RUN_KEY, "/v", MONITOR_VALUE, "/t", "REG_SZ", "/d", &command, "/f"]);
        if result { vec!["[완료] 로그인 시 저메모리 실시간 감시 자동 시작을 켰습니다.".into(), "중복 watcher 실행은 자동 차단되며, 기존 경로가 달랐다면 현재 경로로 복구했습니다.".into()] }
        else { vec!["[오류] 실시간 감시 자동 시작 항목을 등록하지 못했습니다.".into()] }
    }
}

pub fn toggle_db_autoupdate() -> Vec<String> {
    if db_autoupdate_enabled() {
        let result = hidden_status("schtasks.exe", &["/Delete", "/F", "/TN", DB_TASK]);
        if result { vec!["[완료] DB 주기 자동 업데이트를 껐습니다.".into()] }
        else { vec!["[오류] DB 자동 업데이트 작업을 제거하지 못했습니다.".into()] }
    } else {
        let Some(command) = exe_command("--update-data-silent") else { return vec!["[오류] QuietGuard 실행 파일 경로를 확인하지 못했습니다.".into()]; };
        let result = hidden_status("schtasks.exe", &["/Create", "/F", "/SC", "HOURLY", "/MO", DB_TASK_HOURS, "/TN", DB_TASK, "/TR", &command, "/RL", "LIMITED"]);
        if result {
            vec!["[완료] DB 주기 자동 업데이트를 켰습니다.".into(),
                 "예약 실행: 6시간마다. 각 소스의 갱신 주기가 아니면 실제 다운로드는 건너뜁니다.".into(),
                 "ThreatFox/URLhaus 6h · QuietGuard 규칙 확인 6h · 공개/한국 목록 24h · ClamAV 24h".into(),
                 "기존 예약 작업의 실행 경로가 달랐다면 현재 QuietGuard 경로로 복구했습니다.".into()]
        } else {
            vec!["[오류] DB 자동 업데이트 예약 작업을 만들지 못했습니다.".into(), "현재 사용자 권한에서 작업 스케줄러 등록이 허용되는지 확인이 필요합니다.".into()]
        }
    }
}

pub fn toggle_app_autoupdate() -> Vec<String> {
    if app_autoupdate_enabled() {
        let result = hidden_status("schtasks.exe", &["/Delete", "/F", "/TN", APP_TASK]);
        if result { vec!["[완료] QuietGuard 프로그램 자동 업데이트를 껐습니다.".into()] }
        else { vec!["[오류] 프로그램 자동 업데이트 작업을 제거하지 못했습니다.".into()] }
    } else {
        let Some(command) = exe_command("--self-update-silent") else { return vec!["[오류] QuietGuard 실행 파일 경로를 확인하지 못했습니다.".into()]; };
        let result = hidden_status("schtasks.exe", &["/Create", "/F", "/SC", "HOURLY", "/MO", APP_TASK_HOURS, "/TN", APP_TASK, "/TR", &command, "/RL", "LIMITED"]);
        if result {
            vec![
                "[완료] QuietGuard 프로그램 자동 업데이트를 켰습니다.".into(),
                "GitHub의 최신 정식 Release를 6시간마다 확인합니다.".into(),
                "새 버전 발견 시 ZIP과 SHA-256을 내려받아 검증한 뒤 안전 교체를 시도합니다.".into(),
                "업데이트 중 다른 QuietGuard 창이 실행 중이면 다음 예약 실행 때 다시 시도합니다.".into(),
            ]
        } else {
            vec!["[오류] 프로그램 자동 업데이트 예약 작업을 만들지 못했습니다.".into(), "현재 사용자 권한에서 작업 스케줄러 등록이 허용되는지 확인이 필요합니다.".into()]
        }
    }
}

pub fn status_lines() -> Vec<String> {
    vec![
        format!("Windows 시작 시 QuietGuard: {}", startup_registration_status(STARTUP_VALUE, "")),
        format!("실시간 감시 자동 시작: {}", startup_registration_status(MONITOR_VALUE, "--watch")),
        format!("DB 주기 자동 업데이트: {} (고정 6시간 스케줄 / 소스별 고정 주기)", db_registration_status()),
        format!("프로그램 자동 업데이트: {} (GitHub 정식 Release / 6시간 확인)", app_registration_status()),
        "DB 고정 주기: ThreatFox/URLhaus 6h · QuietGuard 규칙 확인 6h · 공개 PUP/도메인 24h · YousList 24h · ClamAV 24h".into(),
    ]
}

pub fn windows_startup_enabled() -> bool {
    exe_command("").map(|expected| reg_value_matches(STARTUP_VALUE, &expected)).unwrap_or(false)
}

pub fn monitor_autostart_enabled() -> bool {
    exe_command("--watch").map(|expected| reg_value_matches(MONITOR_VALUE, &expected)).unwrap_or(false)
}

pub fn db_autoupdate_enabled() -> bool {
    task_matches(DB_TASK, "--update-data-silent")
}

pub fn app_autoupdate_enabled() -> bool {
    task_matches(APP_TASK, "--self-update-silent")
}

fn task_matches(task: &str, arg: &str) -> bool {
    let Some(exe) = env::current_exe().ok() else { return false; };
    let text = hidden_text("schtasks.exe", &["/Query", "/TN", task, "/FO", "LIST", "/V"]);
    if text.is_empty() { return false; }
    let lower = text.to_ascii_lowercase();
    lower.contains(&exe.to_string_lossy().to_ascii_lowercase()) && lower.contains(&arg.to_ascii_lowercase())
}

fn startup_registration_status(name: &str, arg: &str) -> &'static str {
    let Some(expected) = exe_command(arg) else { return "확인 불가"; };
    if reg_value_matches(name, &expected) { "켜짐" }
    else if reg_value_exists(name) { "등록 경로 불일치 (설정 버튼으로 복구 가능)" }
    else { "꺼짐" }
}

fn db_registration_status() -> &'static str {
    task_registration_status(DB_TASK, "--update-data-silent")
}

fn app_registration_status() -> &'static str {
    task_registration_status(APP_TASK, "--self-update-silent")
}

fn task_registration_status(task: &str, arg: &str) -> &'static str {
    if task_matches(task, arg) { "켜짐" }
    else if task_exists(task) { "등록 경로 불일치 (설정 버튼으로 복구 가능)" }
    else { "꺼짐" }
}

fn reg_value_exists(name: &str) -> bool {
    hidden_status("reg.exe", &["query", RUN_KEY, "/v", name])
}

fn reg_value_matches(name: &str, expected: &str) -> bool {
    let text = hidden_text("reg.exe", &["query", RUN_KEY, "/v", name]);
    !text.is_empty() && text.to_ascii_lowercase().contains(&expected.to_ascii_lowercase())
}

fn task_exists(task: &str) -> bool {
    hidden_status("schtasks.exe", &["/Query", "/TN", task])
}

fn exe_command(arg: &str) -> Option<String> {
    let exe = env::current_exe().ok()?;
    let path = exe.to_string_lossy();
    if arg.is_empty() { Some(format!("\"{}\"", path)) } else { Some(format!("\"{}\" {}", path, arg)) }
}

fn hidden_status(program: &str, args: &[&str]) -> bool {
    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.status().map(|s| s.success()).unwrap_or(false)
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
    if bytes.starts_with(&[0xFE, 0xFF]) {
        let u16s: Vec<u16> = bytes[2..].chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
        return String::from_utf16_lossy(&u16s);
    }
    String::from_utf8_lossy(bytes).into_owned()
}
