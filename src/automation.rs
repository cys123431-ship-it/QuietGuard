use std::env;
use std::os::windows::process::CommandExt;
use std::process::Command;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const RUN_KEY: &str = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
const STARTUP_VALUE: &str = "QuietGuard";
const MONITOR_VALUE: &str = "QuietGuardMonitor";
const DB_TASK: &str = "QuietGuard DB Update";
const DB_TASK_HOURS: &str = "6";

pub fn toggle_windows_startup() -> Vec<String> {
    if windows_startup_enabled() {
        let result = hidden_status("reg.exe", &["delete", RUN_KEY, "/v", STARTUP_VALUE, "/f"]);
        if result { vec!["[완료] Windows 로그인 시 QuietGuard 자동 실행을 껐습니다.".into()] }
        else { vec!["[오류] Windows 자동 실행 항목을 제거하지 못했습니다.".into()] }
    } else {
        let Some(command) = exe_command("") else { return vec!["[오류] QuietGuard 실행 파일 경로를 확인하지 못했습니다.".into()]; };
        let result = hidden_status("reg.exe", &["add", RUN_KEY, "/v", STARTUP_VALUE, "/t", "REG_SZ", "/d", &command, "/f"]);
        if result { vec!["[완료] Windows 로그인 시 QuietGuard 자동 실행을 켰습니다.".into(), "사용자가 이 버튼을 눌러 켠 경우에만 유지됩니다.".into()] }
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
        if result { vec!["[완료] 로그인 시 저메모리 실시간 감시 자동 시작을 켰습니다.".into(), "중복 watcher 실행은 자동 차단됩니다.".into()] }
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
                 "예약 실행: 6시간마다. 소스별 최적 주기가 아니면 다운로드를 건너뜁니다.".into(),
                 "ThreatFox/URLhaus 6h · ClamAV 12h · 공개 PUP/도메인 72h · YousList 72h".into()]
        } else {
            vec!["[오류] DB 자동 업데이트 예약 작업을 만들지 못했습니다.".into(), "현재 사용자 권한에서 작업 스케줄러 등록이 허용되는지 확인이 필요합니다.".into()]
        }
    }
}

pub fn status_lines() -> Vec<String> {
    vec![
        format!("Windows 시작 시 QuietGuard: {}", on_off(windows_startup_enabled())),
        format!("실시간 감시 자동 시작: {}", on_off(monitor_autostart_enabled())),
        format!("DB 주기 자동 업데이트: {} (고정 6시간 스케줄 / 소스별 주기 적용)", on_off(db_autoupdate_enabled())),
        "DB 최적 주기: ThreatFox/URLhaus 6h · ClamAV 12h · 공개 PUP/도메인 72h · YousList 72h".into(),
    ]
}

pub fn windows_startup_enabled() -> bool { reg_value_exists(STARTUP_VALUE) }
pub fn monitor_autostart_enabled() -> bool { reg_value_exists(MONITOR_VALUE) }
pub fn db_autoupdate_enabled() -> bool { hidden_status("schtasks.exe", &["/Query", "/TN", DB_TASK]) }

fn reg_value_exists(name: &str) -> bool { hidden_status("reg.exe", &["query", RUN_KEY, "/v", name]) }

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

fn on_off(value: bool) -> &'static str { if value { "켜짐" } else { "꺼짐" } }
