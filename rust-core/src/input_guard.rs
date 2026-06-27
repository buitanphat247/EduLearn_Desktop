#[cfg(target_os = "windows")]
mod windows_impl {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc, Arc, Mutex, OnceLock};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use windows::Win32::Foundation::{HINSTANCE, LPARAM, LRESULT, WPARAM};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        GetAsyncKeyState, VIRTUAL_KEY, VK_APPS, VK_CONTROL, VK_D, VK_ESCAPE, VK_F4, VK_F12,
        VK_LWIN, VK_MENU, VK_RWIN, VK_SHIFT, VK_TAB,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        CallNextHookEx, DispatchMessageW, GetMessageW, KBDLLHOOKSTRUCT, SetWindowsHookExW,
        UnhookWindowsHookEx, HC_ACTION, HHOOK, MSG, TranslateMessage, WH_KEYBOARD_LL, WM_KEYDOWN,
        WM_QUIT, WM_SYSKEYDOWN,
    };

    #[derive(Debug, Clone)]
    pub struct InputGuardMutationResult {
        pub applied: bool,
        pub active: bool,
        pub detail: String,
    }

    struct InputGuardHandle {
        stop_flag: Arc<AtomicBool>,
        thread: JoinHandle<()>,
    }

    static INPUT_GUARD_STATE: OnceLock<Mutex<Option<InputGuardHandle>>> = OnceLock::new();
    static INPUT_GUARD_ACTIVE: AtomicBool = AtomicBool::new(false);

    fn input_guard_state() -> &'static Mutex<Option<InputGuardHandle>> {
        INPUT_GUARD_STATE.get_or_init(|| Mutex::new(None))
    }

    fn is_virtual_key_down(key: VIRTUAL_KEY) -> bool {
        unsafe { GetAsyncKeyState(i32::from(key.0)) < 0 }
    }

    fn should_allow_dev_escape(vk_code: u32) -> bool {
        vk_code == u32::from(VK_F12.0) && is_virtual_key_down(VK_CONTROL) && is_virtual_key_down(VK_SHIFT)
    }

    fn should_block_shortcut(vk_code: u32) -> bool {
        if should_allow_dev_escape(vk_code) {
            return false;
        }

        let alt_down = is_virtual_key_down(VK_MENU);
        let ctrl_down = is_virtual_key_down(VK_CONTROL);
        let win_down = is_virtual_key_down(VK_LWIN) || is_virtual_key_down(VK_RWIN);

        if vk_code == u32::from(VK_LWIN.0) || vk_code == u32::from(VK_RWIN.0) {
            return true;
        }

        if vk_code == u32::from(VK_TAB.0) && (alt_down || win_down) {
            return true;
        }

        if vk_code == u32::from(VK_ESCAPE.0) && (alt_down || ctrl_down) {
            return true;
        }

        if vk_code == u32::from(VK_F4.0) && alt_down {
            return true;
        }

        if vk_code == u32::from(VK_D.0) && win_down {
            return true;
        }

        if vk_code == u32::from(VK_APPS.0) {
            return true;
        }

        false
    }

    unsafe extern "system" fn keyboard_hook_proc(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
        if code == HC_ACTION as i32 && INPUT_GUARD_ACTIVE.load(Ordering::SeqCst) {
            let message = wparam.0 as u32;
            if message == WM_KEYDOWN || message == WM_SYSKEYDOWN {
                let keyboard_info = unsafe { &*(lparam.0 as *const KBDLLHOOKSTRUCT) };
                if should_block_shortcut(keyboard_info.vkCode) {
                    return LRESULT(1);
                }
            }
        }

        unsafe { CallNextHookEx(HHOOK::default(), code, wparam, lparam) }
    }

    fn spawn_input_guard_thread(
        stop_flag: Arc<AtomicBool>,
        ready_tx: mpsc::Sender<Result<(), String>>,
    ) -> JoinHandle<()> {
        thread::spawn(move || {
            let module_handle = match unsafe { GetModuleHandleW(None) } {
                Ok(handle) => handle,
                Err(error) => {
                    let _ = ready_tx.send(Err(format!("GetModuleHandleW failed: {error}")));
                    return;
                }
            };

            let keyboard_hook = match unsafe {
                SetWindowsHookExW(WH_KEYBOARD_LL, Some(keyboard_hook_proc), HINSTANCE(module_handle.0), 0)
            } {
                Ok(handle) => handle,
                Err(error) => {
                    let _ = ready_tx.send(Err(format!("SetWindowsHookExW failed: {error}")));
                    return;
                }
            };

            INPUT_GUARD_ACTIVE.store(true, Ordering::SeqCst);
            let _ = ready_tx.send(Ok(()));

            let mut message = MSG::default();
            loop {
                if stop_flag.load(Ordering::SeqCst) {
                    break;
                }

                let result = unsafe { GetMessageW(&mut message, None, 0, 0) };
                if result.0 == -1 {
                    break;
                }

                if result.0 == 0 || message.message == WM_QUIT {
                    break;
                }

                unsafe {
                    let _ = TranslateMessage(&message);
                    DispatchMessageW(&message);
                }

                if stop_flag.load(Ordering::SeqCst) {
                    break;
                }

                thread::sleep(Duration::from_millis(4));
            }

            let _ = unsafe { UnhookWindowsHookEx(keyboard_hook) };
            INPUT_GUARD_ACTIVE.store(false, Ordering::SeqCst);
        })
    }

    pub fn activate_input_guard() -> InputGuardMutationResult {
        let state = input_guard_state();
        let mut guard = match state.lock() {
            Ok(value) => value,
            Err(_) => {
                return InputGuardMutationResult {
                    applied: false,
                    active: false,
                    detail: "Input guard state lock is poisoned.".to_string(),
                }
            }
        };

        if guard.is_some() && INPUT_GUARD_ACTIVE.load(Ordering::SeqCst) {
            return InputGuardMutationResult {
                applied: true,
                active: true,
                detail: "Native keyboard hook is already active.".to_string(),
            };
        }

        let stop_flag = Arc::new(AtomicBool::new(false));
        let (ready_tx, ready_rx) = mpsc::channel();
        let thread = spawn_input_guard_thread(Arc::clone(&stop_flag), ready_tx);

        match ready_rx.recv_timeout(Duration::from_secs(3)) {
            Ok(Ok(())) => {
                *guard = Some(InputGuardHandle { stop_flag, thread });
                InputGuardMutationResult {
                    applied: true,
                    active: true,
                    detail: "Native keyboard hook is active. Alt+Tab, Win and common escape shortcuts are now blocked at the desktop core layer.".to_string(),
                }
            }
            Ok(Err(error)) => {
                stop_flag.store(true, Ordering::SeqCst);
                let _ = thread.join();
                InputGuardMutationResult {
                    applied: false,
                    active: false,
                    detail: error,
                }
            }
            Err(_) => {
                stop_flag.store(true, Ordering::SeqCst);
                let _ = thread.join();
                InputGuardMutationResult {
                    applied: false,
                    active: false,
                    detail: "Timed out while waiting for the native keyboard hook to start.".to_string(),
                }
            }
        }
    }

    pub fn deactivate_input_guard() -> InputGuardMutationResult {
        let state = input_guard_state();
        let mut guard = match state.lock() {
            Ok(value) => value,
            Err(_) => {
                return InputGuardMutationResult {
                    applied: false,
                    active: INPUT_GUARD_ACTIVE.load(Ordering::SeqCst),
                    detail: "Input guard state lock is poisoned during restore.".to_string(),
                }
            }
        };

        if let Some(handle) = guard.take() {
            handle.stop_flag.store(true, Ordering::SeqCst);
            let _ = handle.thread.join();

            return InputGuardMutationResult {
                applied: true,
                active: false,
                detail: "Native keyboard hook was removed and desktop shortcuts were restored.".to_string(),
            };
        }

        InputGuardMutationResult {
            applied: true,
            active: false,
            detail: "Native keyboard hook was already inactive.".to_string(),
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod windows_impl {
    #[derive(Debug, Clone)]
    pub struct InputGuardMutationResult {
        pub applied: bool,
        pub active: bool,
        pub detail: String,
    }

    pub fn activate_input_guard() -> InputGuardMutationResult {
        InputGuardMutationResult {
            applied: false,
            active: false,
            detail: "Native input guard is only supported on Windows.".to_string(),
        }
    }

    pub fn deactivate_input_guard() -> InputGuardMutationResult {
        InputGuardMutationResult {
            applied: false,
            active: false,
            detail: "Native input guard restore is only supported on Windows.".to_string(),
        }
    }
}

pub use windows_impl::{activate_input_guard, deactivate_input_guard, InputGuardMutationResult};
