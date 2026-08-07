use std::io::{Read, Write};
use std::net::{SocketAddrV4, TcpStream};
use std::ptr::{null, null_mut};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    BeginPaint, COLOR_BTNFACE, COLOR_HIGHLIGHT, COLOR_WINDOW, DT_CENTER, DT_SINGLELINE, DT_VCENTER,
    DrawTextW, EndPaint, FillRect, PAINTSTRUCT, UpdateWindow,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::SystemServices::SS_LEFT;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{ReleaseCapture, SetCapture};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    BS_PUSHBUTTON, CW_USEDEFAULT, CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW,
    GWLP_USERDATA, GetMessageW, GetWindowLongPtrW, HMENU, MSG, PostMessageW, PostQuitMessage,
    RegisterClassW, SW_SHOW, SetWindowLongPtrW, SetWindowTextW, ShowWindow, TranslateMessage,
    WM_CLOSE, WM_COMMAND, WM_DESTROY, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_PAINT, WNDCLASSW, WS_CHILD,
    WS_OVERLAPPEDWINDOW, WS_TABSTOP, WS_VISIBLE,
};

const WINDOW_TITLE: &str = "Satelle native readiness probe";
const BUTTON_ID: usize = 100;
const WINDOW_WIDTH: i32 = 1024;
const WINDOW_HEIGHT: i32 = 678;
const SOURCE_RECT: RECT = RECT {
    left: 140,
    top: 260,
    right: 320,
    bottom: 390,
};
const TARGET_RECT: RECT = RECT {
    left: 560,
    top: 365,
    right: 760,
    bottom: 495,
};

pub(crate) struct WindowsNativeProbeWindow {
    hwnd: isize,
    worker: Option<JoinHandle<()>>,
}

struct ProbeCallback {
    address: SocketAddrV4,
    completion_target: String,
    nonce: String,
}

struct WindowState {
    callback: ProbeCallback,
    click_status: HWND,
    drag_status: HWND,
    click_observed: bool,
    drag_observed: bool,
    drag_started: bool,
}

impl WindowsNativeProbeWindow {
    pub(crate) fn spawn(
        address: SocketAddrV4,
        capability: &str,
        nonce: &str,
    ) -> std::io::Result<Self> {
        let callback = ProbeCallback {
            address,
            completion_target: format!("/complete/{capability}"),
            nonce: nonce.to_string(),
        };
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("satelle-native-probe-window".to_string())
            .spawn(move || run_window(callback, ready_sender))?;
        match ready_receiver.recv() {
            Ok(Ok(hwnd)) => Ok(Self {
                hwnd,
                worker: Some(worker),
            }),
            Ok(Err(error)) => {
                let _ = worker.join();
                Err(error)
            }
            Err(_) => {
                let _ = worker.join();
                Err(std::io::Error::other(
                    "the native probe window stopped before becoming ready",
                ))
            }
        }
    }
}

impl Drop for WindowsNativeProbeWindow {
    fn drop(&mut self) {
        // HWND is thread-affine for direct destruction. Posting WM_CLOSE lets
        // the owning message loop destroy the window and release its state.
        unsafe {
            PostMessageW(self.hwnd as HWND, WM_CLOSE, 0, 0);
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn run_window(callback: ProbeCallback, ready_sender: mpsc::SyncSender<std::io::Result<isize>>) {
    let class_name = wide("SatelleNativeReadinessProbe");
    let title = wide(WINDOW_TITLE);
    let instance = unsafe { GetModuleHandleW(null()) };
    if instance.is_null() {
        let _ = ready_sender.send(Err(std::io::Error::last_os_error()));
        return;
    }

    let window_class = WNDCLASSW {
        lpfnWndProc: Some(window_proc),
        hInstance: instance,
        hbrBackground: (COLOR_WINDOW + 1) as usize as _,
        lpszClassName: class_name.as_ptr(),
        ..WNDCLASSW::default()
    };
    // A zero result is harmless when an earlier probe in this process already
    // registered this exact class. CreateWindowExW is the definitive check.
    unsafe {
        RegisterClassW(&window_class);
    }
    let hwnd = unsafe {
        CreateWindowExW(
            0,
            class_name.as_ptr(),
            title.as_ptr(),
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            WINDOW_WIDTH,
            WINDOW_HEIGHT,
            null_mut(),
            null_mut(),
            instance,
            null(),
        )
    };
    if hwnd.is_null() {
        let _ = ready_sender.send(Err(std::io::Error::last_os_error()));
        return;
    }

    let state = Box::into_raw(Box::new(WindowState {
        callback,
        click_status: null_mut(),
        drag_status: null_mut(),
        click_observed: false,
        drag_observed: false,
        drag_started: false,
    }));
    unsafe {
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, state as isize);
    }
    let controls = create_controls(hwnd, instance, state);
    if let Err(error) = controls {
        unsafe {
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            DestroyWindow(hwnd);
            drop(Box::from_raw(state));
        }
        let _ = ready_sender.send(Err(error));
        return;
    }

    unsafe {
        ShowWindow(hwnd, SW_SHOW);
        UpdateWindow(hwnd);
    }
    if ready_sender.send(Ok(hwnd as isize)).is_err() {
        unsafe {
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            DestroyWindow(hwnd);
            drop(Box::from_raw(state));
        }
        return;
    }

    let mut message = MSG::default();
    while unsafe { GetMessageW(&mut message, null_mut(), 0, 0) } > 0 {
        unsafe {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    unsafe {
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        drop(Box::from_raw(state));
    }
}

fn create_controls(
    hwnd: HWND,
    instance: windows_sys::Win32::Foundation::HINSTANCE,
    state: *mut WindowState,
) -> std::io::Result<()> {
    let button_class = wide("BUTTON");
    let static_class = wide("STATIC");
    let button_text = wide("Click to confirm");
    let instructions = wide("Complete both native actions to verify Computer Use readiness.");
    let click_pending = wide("Click pending");
    let drag_pending = wide("Drag pending");
    let source_label = wide("Drag from here");
    let target_label = wide("Drop here");

    let button = unsafe {
        CreateWindowExW(
            0,
            button_class.as_ptr(),
            button_text.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON as u32,
            80,
            115,
            220,
            55,
            hwnd,
            BUTTON_ID as HMENU,
            instance,
            null(),
        )
    };
    let instruction_label = create_static(
        hwnd,
        instance,
        &static_class,
        &instructions,
        RECT {
            left: 80,
            top: 55,
            right: 850,
            bottom: 90,
        },
    );
    let click_status = create_static(
        hwnd,
        instance,
        &static_class,
        &click_pending,
        RECT {
            left: 340,
            top: 115,
            right: 700,
            bottom: 150,
        },
    );
    let drag_status = create_static(
        hwnd,
        instance,
        &static_class,
        &drag_pending,
        RECT {
            left: 340,
            top: 165,
            right: 700,
            bottom: 200,
        },
    );
    let source = create_static(
        hwnd,
        instance,
        &static_class,
        &source_label,
        RECT {
            left: SOURCE_RECT.left,
            top: SOURCE_RECT.top - 35,
            right: SOURCE_RECT.right,
            bottom: SOURCE_RECT.top - 5,
        },
    );
    let target = create_static(
        hwnd,
        instance,
        &static_class,
        &target_label,
        RECT {
            left: TARGET_RECT.left,
            top: TARGET_RECT.top - 35,
            right: TARGET_RECT.right,
            bottom: TARGET_RECT.top - 5,
        },
    );
    if button.is_null()
        || instruction_label.is_null()
        || click_status.is_null()
        || drag_status.is_null()
        || source.is_null()
        || target.is_null()
    {
        return Err(std::io::Error::last_os_error());
    }
    unsafe {
        (*state).click_status = click_status;
        (*state).drag_status = drag_status;
    }
    Ok(())
}

fn create_static(
    parent: HWND,
    instance: windows_sys::Win32::Foundation::HINSTANCE,
    class: &[u16],
    text: &[u16],
    bounds: RECT,
) -> HWND {
    unsafe {
        CreateWindowExW(
            0,
            class.as_ptr(),
            text.as_ptr(),
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            bounds.left,
            bounds.top,
            bounds.right - bounds.left,
            bounds.bottom - bounds.top,
            parent,
            null_mut(),
            instance,
            null(),
        )
    }
}

unsafe extern "system" fn window_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    let state = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut WindowState };
    match message {
        WM_COMMAND if !state.is_null() && wparam & 0xffff == BUTTON_ID => {
            let state = unsafe { &mut *state };
            if !state.click_observed && state.callback.send_action("click") {
                state.click_observed = true;
                let observed = wide("Click event observed");
                unsafe {
                    SetWindowTextW(state.click_status, observed.as_ptr());
                }
            }
            0
        }
        WM_LBUTTONDOWN if !state.is_null() => {
            let state = unsafe { &mut *state };
            state.drag_started = point_in_rect(SOURCE_RECT, mouse_point(lparam));
            if state.drag_started {
                unsafe {
                    SetCapture(hwnd);
                }
            }
            0
        }
        WM_LBUTTONUP if !state.is_null() => {
            let state = unsafe { &mut *state };
            let completed = state.drag_started && point_in_rect(TARGET_RECT, mouse_point(lparam));
            state.drag_started = false;
            unsafe {
                ReleaseCapture();
            }
            if completed && !state.drag_observed && state.callback.send_action("drag") {
                state.drag_observed = true;
                let observed = wide("Drag event observed");
                unsafe {
                    SetWindowTextW(state.drag_status, observed.as_ptr());
                }
            }
            0
        }
        WM_PAINT => {
            paint_drag_surface(hwnd);
            0
        }
        WM_DESTROY => {
            unsafe {
                PostQuitMessage(0);
            }
            0
        }
        _ => unsafe { DefWindowProcW(hwnd, message, wparam, lparam) },
    }
}

fn paint_drag_surface(hwnd: HWND) {
    let mut paint = PAINTSTRUCT::default();
    let device = unsafe { BeginPaint(hwnd, &mut paint) };
    if device.is_null() {
        return;
    }
    let source_brush = (COLOR_HIGHLIGHT + 1) as usize as _;
    let target_brush = (COLOR_BTNFACE + 1) as usize as _;
    let mut source = SOURCE_RECT;
    let mut target = TARGET_RECT;
    unsafe {
        FillRect(device, &source, source_brush);
        FillRect(device, &target, target_brush);
    }
    let source_text = wide("START");
    let target_text = wide("TARGET");
    unsafe {
        DrawTextW(
            device,
            source_text.as_ptr(),
            -1,
            &mut source,
            DT_CENTER | DT_VCENTER | DT_SINGLELINE,
        );
        DrawTextW(
            device,
            target_text.as_ptr(),
            -1,
            &mut target,
            DT_CENTER | DT_VCENTER | DT_SINGLELINE,
        );
        EndPaint(hwnd, &paint);
    }
}

impl ProbeCallback {
    fn send_action(&self, action: &str) -> bool {
        let body = format!("nonce={}&action={action}", self.nonce);
        let request = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nOrigin: http://{}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            self.completion_target,
            self.address,
            self.address,
            body.len(),
            body
        );
        let Ok(mut stream) = TcpStream::connect_timeout(
            &std::net::SocketAddr::V4(self.address),
            Duration::from_millis(500),
        ) else {
            return false;
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
        let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
        if stream.write_all(request.as_bytes()).is_err() {
            return false;
        }
        let mut response = String::new();
        stream.read_to_string(&mut response).is_ok()
            && response.starts_with("HTTP/1.1 204 No Content")
    }
}

fn mouse_point(lparam: LPARAM) -> (i32, i32) {
    let packed = lparam as u32;
    (
        (packed as u16) as i16 as i32,
        (packed >> 16) as u16 as i16 as i32,
    )
}

fn point_in_rect(rect: RECT, point: (i32, i32)) -> bool {
    point.0 >= rect.left && point.0 < rect.right && point.1 >= rect.top && point.1 < rect.bottom
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
