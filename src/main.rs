#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

#[cfg(not(target_os = "windows"))]
fn main() {
    println!("QuietGuard targets Windows 10/11.");
}

#[cfg(target_os = "windows")]
mod app {
    use std::ffi::c_void;
    use std::fs;
    use std::mem::zeroed;
    use std::process::Command;
    use std::ptr::{null, null_mut};

    type HINSTANCE = *mut c_void;
    type HWND = *mut c_void;
    type HMENU = *mut c_void;
    type HBRUSH = *mut c_void;
    type HCURSOR = *mut c_void;
    type HICON = *mut c_void;
    type LPARAM = isize;
    type WPARAM = usize;
    type LRESULT = isize;
    type UINT = u32;
    type DWORD = u32;
    type ATOM = u16;
    type LPCWSTR = *const u16;

    #[repr(C)]
    struct WNDCLASSW {
        style: UINT,
        lpfn_wnd_proc: Option<unsafe extern "system" fn(HWND, UINT, WPARAM, LPARAM) -> LRESULT>,
        cb_cls_extra: i32,
        cb_wnd_extra: i32,
        h_instance: HINSTANCE,
        h_icon: HICON,
        h_cursor: HCURSOR,
        hbr_background: HBRUSH,
        lpsz_menu_name: LPCWSTR,
        lpsz_class_name: LPCWSTR,
    }

    #[repr(C)]
    struct MSG {
        hwnd: HWND,
        message: UINT,
        w_param: WPARAM,
        l_param: LPARAM,
        time: DWORD,
        pt_x: i32,
        pt_y: i32,
        l_private: DWORD,
    }

    const WS_OVERLAPPEDWINDOW: DWORD = 0x00CF0000;
    const WS_VISIBLE: DWORD = 0x10000000;
    const WS_CHILD: DWORD = 0x40000000;
    const WS_BORDER: DWORD = 0x00800000;
    const BS_PUSHBUTTON: DWORD = 0x00000000;
    const LBS_NOINTEGRALHEIGHT: DWORD = 0x0100;
    const CW_USEDEFAULT: i32 = 0x80000000u32 as i32;
    const SW_SHOW: i32 = 5;
    const WM_DESTROY: UINT = 0x0002;
    const WM_COMMAND: UINT = 0x0111;
    const LB_ADDSTRING: UINT = 0x0180;
    const LB_RESETCONTENT: UINT = 0x0184;
    const COLOR_WINDOW: isize = 5;
    const IDC_ARROW: LPCWSTR = 32512usize as LPCWSTR;
    const ID_SCAN: usize = 1001;

    static mut LISTBOX: HWND = null_mut();

    #[link(name = "user32")]
    extern "system" {
        fn RegisterClassW(lpWndClass: *const WNDCLASSW) -> ATOM;
        fn CreateWindowExW(dwExStyle: DWORD, lpClassName: LPCWSTR, lpWindowName: LPCWSTR,
            dwStyle: DWORD, x: i32, y: i32, nWidth: i32, nHeight: i32,
            hWndParent: HWND, hMenu: HMENU, hInstance: HINSTANCE, lpParam: *mut c_void) -> HWND;
        fn DefWindowProcW(hWnd: HWND, Msg: UINT, wParam: WPARAM, lParam: LPARAM) -> LRESULT;
        fn ShowWindow(hWnd: HWND, nCmdShow: i32) -> i32;
        fn UpdateWindow(hWnd: HWND) -> i32;
        fn GetMessageW(lpMsg: *mut MSG, hWnd: HWND, wMsgFilterMin: UINT, wMsgFilterMax: UINT) -> i32;
        fn TranslateMessage(lpMsg: *const MSG) -> i32;
        fn DispatchMessageW(lpMsg: *const MSG) -> LRESULT;
        fn PostQuitMessage(nExitCode: i32);
        fn LoadCursorW(hInstance: HINSTANCE, lpCursorName: LPCWSTR) -> HCURSOR;
        fn SendMessageW(hWnd: HWND, Msg: UINT, wParam: WPARAM, lParam: LPARAM) -> LRESULT;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetModuleHandleW(lpModuleName: LPCWSTR) -> HINSTANCE;
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    unsafe fn add_line(text: &str) {
        let w = wide(text);
        SendMessageW(LISTBOX, LB_ADDSTRING, 0, w.as_ptr() as LPARAM);
    }

    fn command_output(program: &str, args: &[&str]) -> String {
        match Command::new(program).args(args).output() {
            Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
            Err(_) => String::new(),
        }
    }

    unsafe fn run_scan() {
        SendMessageW(LISTBOX, LB_RESETCONTENT, 0, 0);
        add_line("QuietGuard 빠른 점검을 시작합니다.");

        // 1) Hosts custom entries
        let windir = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".to_string());
        let hosts = format!("{}\\System32\\drivers\\etc\\hosts", windir);
        match fs::read_to_string(&hosts) {
            Ok(content) => {
                let count = content.lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .filter(|l| !l.starts_with("127.0.0.1 localhost") && !l.starts_with("::1 localhost"))
                    .count();
                if count > 0 {
                    add_line(&format!("[주의] Hosts 사용자 정의 항목 {}개 발견", count));
                } else {
                    add_line("[정상] Hosts 특이 항목 없음");
                }
            }
            Err(_) => add_line("[정보] Hosts 파일을 읽지 못했습니다."),
        }

        // 2) Proxy state
        let proxy = command_output("reg", &[
            "query", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            "/v", "ProxyEnable"
        ]);
        if proxy.contains("0x1") {
            add_line("[주의] Windows 프록시가 활성화되어 있습니다.");
        } else {
            add_line("[정상] Windows 프록시 비활성");
        }

        // 3) Startup entries; flag Temp/AppData executables as higher-interest only.
        let run = command_output("reg", &[
            "query", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        ]);
        let mut startup_count = 0usize;
        let mut suspicious_count = 0usize;
        for line in run.lines() {
            let t = line.trim();
            if t.is_empty() || t.starts_with("HKEY_") { continue; }
            if t.contains("REG_SZ") || t.contains("REG_EXPAND_SZ") {
                startup_count += 1;
                let lower = t.to_ascii_lowercase();
                if lower.contains("\\temp\\") || lower.contains("\\appdata\\local\\temp\\") {
                    suspicious_count += 1;
                }
            }
        }
        add_line(&format!("[정보] 사용자 시작 프로그램 {}개", startup_count));
        if suspicious_count > 0 {
            add_line(&format!("[주의] 임시 폴더 기반 시작 항목 {}개", suspicious_count));
        }

        add_line("점검 완료. 현재 버전은 삭제/차단을 수행하지 않습니다.");
    }

    unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: UINT, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
        match msg {
            WM_COMMAND => {
                if (wparam & 0xFFFF) == ID_SCAN {
                    run_scan();
                    return 0;
                }
            }
            WM_DESTROY => {
                PostQuitMessage(0);
                return 0;
            }
            _ => {}
        }
        DefWindowProcW(hwnd, msg, wparam, lparam)
    }

    pub fn run() {
        unsafe {
            let instance = GetModuleHandleW(null());
            let class_name = wide("QuietGuardNativeWindow");
            let wc = WNDCLASSW {
                style: 0,
                lpfn_wnd_proc: Some(wnd_proc),
                cb_cls_extra: 0,
                cb_wnd_extra: 0,
                h_instance: instance,
                h_icon: null_mut(),
                h_cursor: LoadCursorW(null_mut(), IDC_ARROW),
                hbr_background: (COLOR_WINDOW + 1) as HBRUSH,
                lpsz_menu_name: null(),
                lpsz_class_name: class_name.as_ptr(),
            };
            if RegisterClassW(&wc) == 0 { return; }

            let title = wide("QuietGuard 0.1 - PUP / 시스템 변경 점검");
            let hwnd = CreateWindowExW(
                0, class_name.as_ptr(), title.as_ptr(), WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                CW_USEDEFAULT, CW_USEDEFAULT, 760, 500,
                null_mut(), null_mut(), instance, null_mut()
            );
            if hwnd.is_null() { return; }

            let button = wide("BUTTON");
            let button_text = wide("빠른 점검");
            CreateWindowExW(
                0, button.as_ptr(), button_text.as_ptr(), WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                20, 20, 120, 36, hwnd, ID_SCAN as HMENU, instance, null_mut()
            );

            let listbox = wide("LISTBOX");
            LISTBOX = CreateWindowExW(
                0, listbox.as_ptr(), null(), WS_CHILD | WS_VISIBLE | WS_BORDER | LBS_NOINTEGRALHEIGHT,
                20, 72, 700, 350, hwnd, null_mut(), instance, null_mut()
            );

            add_line("QuietGuard 준비됨 - 빠른 점검을 눌러주세요.");
            ShowWindow(hwnd, SW_SHOW);
            UpdateWindow(hwnd);

            let mut msg: MSG = zeroed();
            while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn main() {
    app::run();
}
