use std::env;
use std::ffi::c_void;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::ptr::{null, null_mut};
use std::time::{SystemTime, UNIX_EPOCH};
use std::os::windows::process::CommandExt;

type HANDLE = *mut c_void;
type HKEY = *mut c_void;
type DWORD = u32;
type LPCWSTR = *const u16;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const ERROR_ALREADY_EXISTS: u32 = 183;
const WAIT_OBJECT_0: u32 = 0;
const WAIT_TIMEOUT: u32 = 258;
const WAIT_FAILED: u32 = 0xFFFF_FFFF;
const EVENT_MODIFY_STATE: u32 = 0x0002;
const SYNCHRONIZE: u32 = 0x0010_0000;
const KEY_NOTIFY: u32 = 0x0010;
const REG_NOTIFY_CHANGE_NAME: u32 = 0x0000_0001;
const REG_NOTIFY_CHANGE_LAST_SET: u32 = 0x0000_0004;
const WATCH_TIMEOUT_MS: u32 = 5_000;

const HKEY_CURRENT_USER: HKEY = 0x8000_0001usize as HKEY;
const HKEY_LOCAL_MACHINE: HKEY = 0x8000_0002usize as HKEY;
const MUTEX_NAME: &str = "Local\\QuietGuardWatcherMutex";
const STOP_EVENT_NAME: &str = "Local\\QuietGuardWatcherStop";

#[link(name = "kernel32")]
extern "system" {
    fn CreateMutexW(lpMutexAttributes: *mut c_void, bInitialOwner: i32, lpName: LPCWSTR) -> HANDLE;
    fn OpenMutexW(dwDesiredAccess: DWORD, bInheritHandle: i32, lpName: LPCWSTR) -> HANDLE;
    fn CreateEventW(lpEventAttributes: *mut c_void, bManualReset: i32, bInitialState: i32, lpName: LPCWSTR) -> HANDLE;
    fn OpenEventW(dwDesiredAccess: DWORD, bInheritHandle: i32, lpName: LPCWSTR) -> HANDLE;
    fn SetEvent(hEvent: HANDLE) -> i32;
    fn WaitForMultipleObjects(nCount: DWORD, lpHandles: *const HANDLE, bWaitAll: i32, dwMilliseconds: DWORD) -> DWORD;
    fn GetLastError() -> DWORD;
    fn CloseHandle(hObject: HANDLE) -> i32;
}

#[link(name = "advapi32")]
extern "system" {
    fn RegOpenKeyExW(hKey: HKEY, lpSubKey: LPCWSTR, ulOptions: DWORD, samDesired: DWORD, phkResult: *mut HKEY) -> i32;
    fn RegNotifyChangeKeyValue(
        hKey: HKEY,
        bWatchSubtree: i32,
        dwNotifyFilter: DWORD,
        hEvent: HANDLE,
        fAsynchronous: i32,
    ) -> i32;
    fn RegCloseKey(hKey: HKEY) -> i32;
}

struct RegWatch {
    label: &'static str,
    key: HKEY,
    event: HANDLE,
    subtree: bool,
}

struct FileWatch {
    label: &'static str,
    path: PathBuf,
    stamp: Option<u128>,
}

pub fn start_background() -> String {
    if is_running() {
        return "[정보] 실시간 감시는 이미 실행 중입니다.".into();
    }
    let exe = match env::current_exe() {
        Ok(v) => v,
        Err(e) => return format!("[오류] 실행 파일 경로 확인 실패: {}", e),
    };
    let mut cmd = Command::new(exe);
    cmd.arg("--watch");
    cmd.creation_flags(CREATE_NO_WINDOW);
    match cmd.spawn() {
        Ok(_) => "[완료] 저메모리 실시간 감시를 시작했습니다.".into(),
        Err(e) => format!("[오류] 실시간 감시 시작 실패: {}", e),
    }
}

pub fn request_stop() -> String {
    unsafe {
        let name = wide(STOP_EVENT_NAME);
        let event = OpenEventW(EVENT_MODIFY_STATE, 0, name.as_ptr());
        if event.is_null() {
            return "[정보] 실행 중인 실시간 감시가 없습니다.".into();
        }
        let ok = SetEvent(event);
        CloseHandle(event);
        if ok != 0 {
            "[완료] 실시간 감시 중지를 요청했습니다.".into()
        } else {
            "[오류] 실시간 감시 중지 신호를 보내지 못했습니다.".into()
        }
    }
}

pub fn is_running() -> bool {
    unsafe {
        let name = wide(MUTEX_NAME);
        let handle = OpenMutexW(SYNCHRONIZE, 0, name.as_ptr());
        if handle.is_null() {
            false
        } else {
            CloseHandle(handle);
            true
        }
    }
}

pub fn run_watcher() {
    unsafe {
        let mutex_name = wide(MUTEX_NAME);
        let mutex = CreateMutexW(null_mut(), 0, mutex_name.as_ptr());
        if mutex.is_null() {
            return;
        }
        if GetLastError() == ERROR_ALREADY_EXISTS {
            CloseHandle(mutex);
            return;
        }

        let stop_name = wide(STOP_EVENT_NAME);
        let stop_event = CreateEventW(null_mut(), 1, 0, stop_name.as_ptr());
        if stop_event.is_null() {
            CloseHandle(mutex);
            return;
        }

        let mut watches = Vec::with_capacity(10);
        add_reg_watch(&mut watches, "사용자 시작프로그램", HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run", false);
        add_reg_watch(&mut watches, "Windows 프록시", HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", false);
        add_reg_watch(&mut watches, "시스템 시작프로그램", HKEY_LOCAL_MACHINE,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run", false);
        add_reg_watch(&mut watches, "Winlogon", HKEY_LOCAL_MACHINE,
            "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", false);
        add_reg_watch(&mut watches, "서비스/드라이버", HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Services", true);
        add_reg_watch(&mut watches, "Chrome 정책", HKEY_LOCAL_MACHINE,
            "Software\\Policies\\Google\\Chrome", true);
        add_reg_watch(&mut watches, "Edge 정책", HKEY_LOCAL_MACHINE,
            "Software\\Policies\\Microsoft\\Edge", true);

        let mut file_watches = build_file_watches();
        write_log(&format!("[watcher] 시작 - 레지스트리 감시 {}개 / 파일 위치 {}개", watches.len(), file_watches.len()));
        write_state(true, watches.len(), file_watches.len());

        let mut handles = Vec::with_capacity(watches.len() + 1);
        handles.push(stop_event);
        for w in &watches {
            handles.push(w.event);
        }

        loop {
            let result = WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, WATCH_TIMEOUT_MS);
            if result == WAIT_OBJECT_0 {
                write_log("[watcher] 중지 신호 수신");
                break;
            }
            if result == WAIT_TIMEOUT {
                poll_files(&mut file_watches);
                continue;
            }
            if result == WAIT_FAILED {
                write_log("[watcher] WaitForMultipleObjects 실패");
                break;
            }

            let index = result.saturating_sub(WAIT_OBJECT_0) as usize;
            if index >= 1 && index <= watches.len() {
                let watch_index = index - 1;
                let watch = &watches[watch_index];
                write_log(&format!("[변경] 레지스트리: {}", watch.label));
                arm_watch(watch);
            }
            poll_files(&mut file_watches);
        }

        for watch in watches {
            RegCloseKey(watch.key);
            CloseHandle(watch.event);
        }
        CloseHandle(stop_event);
        CloseHandle(mutex);
        write_state(false, 0, 0);
        write_log("[watcher] 종료");
    }
}

unsafe fn add_reg_watch(
    watches: &mut Vec<RegWatch>,
    label: &'static str,
    root: HKEY,
    subkey: &str,
    subtree: bool,
) {
    let sub = wide(subkey);
    let mut key: HKEY = null_mut();
    if RegOpenKeyExW(root, sub.as_ptr(), 0, KEY_NOTIFY, &mut key) != 0 || key.is_null() {
        return;
    }
    let event = CreateEventW(null_mut(), 0, 0, null());
    if event.is_null() {
        RegCloseKey(key);
        return;
    }
    let watch = RegWatch { label, key, event, subtree };
    if !arm_watch(&watch) {
        RegCloseKey(key);
        CloseHandle(event);
        return;
    }
    watches.push(watch);
}

unsafe fn arm_watch(watch: &RegWatch) -> bool {
    RegNotifyChangeKeyValue(
        watch.key,
        if watch.subtree { 1 } else { 0 },
        REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
        watch.event,
        1,
    ) == 0
}

fn build_file_watches() -> Vec<FileWatch> {
    let mut watches = Vec::with_capacity(4);
    let windir = env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into());
    add_file_watch(&mut watches, "Hosts", PathBuf::from(windir).join("System32\\drivers\\etc\\hosts"));

    if let Ok(appdata) = env::var("APPDATA") {
        add_file_watch(&mut watches, "사용자 Startup", PathBuf::from(appdata)
            .join("Microsoft\\Windows\\Start Menu\\Programs\\Startup"));
    }
    if let Ok(programdata) = env::var("ProgramData") {
        add_file_watch(&mut watches, "전체 사용자 Startup", PathBuf::from(programdata)
            .join("Microsoft\\Windows\\Start Menu\\Programs\\StartUp"));
    }
    watches
}

fn add_file_watch(watches: &mut Vec<FileWatch>, label: &'static str, path: PathBuf) {
    let stamp = modified_stamp(&path);
    watches.push(FileWatch { label, path, stamp });
}

fn poll_files(watches: &mut [FileWatch]) {
    for watch in watches {
        let now = modified_stamp(&watch.path);
        if now != watch.stamp {
            write_log(&format!("[변경] 파일/폴더: {} ({})", watch.label, watch.path.display()));
            watch.stamp = now;
        }
    }
}

fn modified_stamp(path: &PathBuf) -> Option<u128> {
    fs::metadata(path).ok()?.modified().ok()?.duration_since(UNIX_EPOCH).ok().map(|d| d.as_millis())
}

fn data_dir() -> PathBuf {
    if let Ok(local) = env::var("LOCALAPPDATA") {
        return PathBuf::from(local).join("QuietGuard");
    }
    PathBuf::from("QuietGuardData")
}

fn write_log(message: &str) {
    let dir = data_dir();
    let _ = fs::create_dir_all(&dir);
    let path = dir.join("events.log");
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{} {}", ts, message);
    }
}

fn write_state(running: bool, registry_count: usize, file_count: usize) {
    let dir = data_dir();
    let _ = fs::create_dir_all(&dir);
    let path = dir.join("watcher.state");
    let body = if running {
        format!("running=1\nregistry_watches={}\nfile_watches={}\n", registry_count, file_count)
    } else {
        "running=0\n".to_string()
    };
    let _ = fs::write(path, body);
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
