#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

#[cfg(target_os = "windows")]
mod rules;
#[cfg(target_os = "windows")]
mod scanner;
#[cfg(target_os = "windows")]
mod scanner_extra;
#[cfg(target_os = "windows")]
mod scanner_extra2;
#[cfg(target_os = "windows")]
mod updater;
#[cfg(target_os = "windows")]
mod monitor;

#[cfg(not(target_os = "windows"))]
fn main() {
    println!("QuietGuard targets Windows 10/11.");
}

#[cfg(target_os = "windows")]
mod app {
    use std::ffi::c_void;
    use std::mem::zeroed;
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
    const WS_VSCROLL: DWORD = 0x00200000;
    const CW_USEDEFAULT: i32 = 0x80000000u32 as i32;
    const SW_SHOW: i32 = 5;
    const WM_DESTROY: UINT = 0x0002;
    const WM_COMMAND: UINT = 0x0111;
    const LB_ADDSTRING: UINT = 0x0180;
    const LB_RESETCONTENT: UINT = 0x0184;
    const COLOR_WINDOW: isize = 5;
    const IDC_ARROW: LPCWSTR = 32512usize as LPCWSTR;
    const ID_SCAN: usize = 1001;
    const ID_UPDATE: usize = 1002;
    const ID_WATCH_START: usize = 1003;
    const ID_WATCH_STOP: usize = 1004;

    static mut LISTBOX: HWND = null_mut();

    #[link(name = "user32")]
    extern "system" {
        fn RegisterClassW(lpWndClass: *const WNDCLASSW) -> ATOM;
        fn CreateWindowExW(
            dwExStyle: DWORD, lpClassName: LPCWSTR, lpWindowName: LPCWSTR,
            dwStyle: DWORD, x: i32, y: i32, nWidth: i32, nHeight: i32,
            hWndParent: HWND, hMenu: HMENU, hInstance: HINSTANCE, lpParam: *mut c_void
        ) -> HWND;
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

    unsafe fn clear_results() {
        SendMessageW(LISTBOX, LB_RESETCONTENT, 0, 0);
    }

    unsafe fn run_scan() {
        clear_results();
        for line in crate::scanner::run_quick_scan() {
            add_line(&line);
        }
        for line in crate::scanner_extra::run_extra_scan() {
            add_line(&line);
        }
        for line in crate::scanner_extra2::run_extra_scan2() {
            add_line(&line);
        }
    }

    unsafe fn run_rule_update() {
        clear_results();
        for line in crate::updater::update_rules() {
            add_line(&line);
        }
    }

    unsafe fn start_watch() {
        clear_results();
        add_line(&crate::monitor::start_background());
        add_line("변경 이벤트는 %LOCALAPPDATA%\\QuietGuard\\events.log 에 기록됩니다.");
    }

    unsafe fn stop_watch() {
        clear_results();
        add_line(&crate::monitor::request_stop());
    }

    unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: UINT, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
        match msg {
            WM_COMMAND => {
                match wparam & 0xFFFF {
                    ID_SCAN => {
                        run_scan();
                        return 0;
                    }
                    ID_UPDATE => {
                        run_rule_update();
                        return 0;
                    }
                    ID_WATCH_START => {
                        start_watch();
                        return 0;
                    }
                    ID_WATCH_STOP => {
                        stop_watch();
                        return 0;
                    }
                    _ => {}
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

            let title = wide("QuietGuard 0.6 - PUP / 시스템 변경 점검");
            let hwnd = CreateWindowExW(
                0, class_name.as_ptr(), title.as_ptr(), WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                CW_USEDEFAULT, CW_USEDEFAULT, 960, 610,
                null_mut(), null_mut(), instance, null_mut()
            );
            if hwnd.is_null() { return; }

            let button = wide("BUTTON");
            let scan_text = wide("시스템 점검");
            CreateWindowExW(
                0, button.as_ptr(), scan_text.as_ptr(), WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                20, 20, 135, 36, hwnd, ID_SCAN as HMENU, instance, null_mut()
            );

            let update_text = wide("규칙 업데이트");
            CreateWindowExW(
                0, button.as_ptr(), update_text.as_ptr(), WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                170, 20, 135, 36, hwnd, ID_UPDATE as HMENU, instance, null_mut()
            );

            let watch_start_text = wide("실시간 감시 시작");
            CreateWindowExW(
                0, button.as_ptr(), watch_start_text.as_ptr(), WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                320, 20, 145, 36, hwnd, ID_WATCH_START as HMENU, instance, null_mut()
            );

            let watch_stop_text = wide("실시간 감시 중지");
            CreateWindowExW(
                0, button.as_ptr(), watch_stop_text.as_ptr(), WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                480, 20, 145, 36, hwnd, ID_WATCH_STOP as HMENU, instance, null_mut()
            );

            let listbox = wide("LISTBOX");
            LISTBOX = CreateWindowExW(
                0, listbox.as_ptr(), null(),
                WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | LBS_NOINTEGRALHEIGHT,
                20, 72, 900, 475, hwnd, null_mut(), instance, null_mut()
            );

            add_line("QuietGuard 준비됨 - 시스템 점검 / 규칙 업데이트 / 실시간 감시를 사용할 수 있습니다.");
            add_line("Defender를 대체하지 않으며 PUP/시스템 변조 흔적을 보조 점검합니다.");
            add_line(if crate::monitor::is_running() {
                "실시간 감시 상태: 실행 중"
            } else {
                "실시간 감시 상태: 중지됨"
            });
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
    if std::env::args().any(|arg| arg == "--watch") {
        monitor::run_watcher();
    } else {
        app::run();
    }
}
