#[cfg(target_os = "windows")]
mod windows_impl {
    use crate::guard_liveness::is_thread_guard_healthy;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc, Arc, Mutex, OnceLock};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use windows::Win32::Foundation::{HINSTANCE, LPARAM, LRESULT, WPARAM};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        GetAsyncKeyState, VIRTUAL_KEY, VK_APPS, VK_C, VK_CONTROL, VK_D, VK_ESCAPE, VK_F4,
        VK_F12, VK_INSERT, VK_LWIN, VK_MENU, VK_RWIN, VK_S, VK_SHIFT, VK_SNAPSHOT, VK_TAB,
        VK_V, VK_X,
    };
    use windows::Win32::System::Threading::GetCurrentThreadId;
    use windows::Win32::UI::WindowsAndMessaging::{
        CallNextHookEx, DispatchMessageW, GetMessageW, KBDLLHOOKSTRUCT, PeekMessageW,
        PostThreadMessageW, SetWindowsHookExW, UnhookWindowsHookEx, HC_ACTION, HHOOK, MSG,
        PM_NOREMOVE, TranslateMessage, WH_KEYBOARD_LL, WM_KEYDOWN, WM_QUIT, WM_SYSKEYDOWN,
    };

    #[derive(Debug, Clone)]
    pub struct InputGuardMutationResult {
        pub applied: bool,
        pub active: bool,
        pub detail: String,
    }

    struct InputGuardHandle {
        stop_flag: Arc<AtomicBool>,
        thread_id: u32,
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

    #[derive(Debug, Clone, Copy, Default)]
    struct KeyModifiers {
        alt: bool,
        ctrl: bool,
        shift: bool,
        win: bool,
    }

    fn current_modifiers() -> KeyModifiers {
        KeyModifiers {
            alt: is_virtual_key_down(VK_MENU),
            ctrl: is_virtual_key_down(VK_CONTROL),
            shift: is_virtual_key_down(VK_SHIFT),
            win: is_virtual_key_down(VK_LWIN) || is_virtual_key_down(VK_RWIN),
        }
    }

    fn is_developer_escape_enabled() -> bool {
        std::env::var("EDULEARN_EXAM_GUARD_DEV_ESCAPE")
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }

    fn should_block_shortcut_with_policy(
        vk_code: u32,
        modifiers: KeyModifiers,
        developer_escape_enabled: bool,
    ) -> bool {
        if vk_code == u32::from(VK_F12.0) && modifiers.ctrl && modifiers.shift {
            return !developer_escape_enabled;
        }

        if vk_code == u32::from(VK_SNAPSHOT.0) {
            return true;
        }

        if vk_code == u32::from(VK_LWIN.0) || vk_code == u32::from(VK_RWIN.0) {
            return true;
        }

        if vk_code == u32::from(VK_S.0) && modifiers.win && modifiers.shift {
            return true;
        }

        if vk_code == u32::from(VK_TAB.0) && (modifiers.alt || modifiers.win) {
            return true;
        }

        if vk_code == u32::from(VK_ESCAPE.0) && (modifiers.alt || modifiers.ctrl) {
            return true;
        }

        if vk_code == u32::from(VK_F4.0) && modifiers.alt {
            return true;
        }

        if vk_code == u32::from(VK_D.0) && modifiers.win {
            return true;
        }

        if vk_code == u32::from(VK_APPS.0) {
            return true;
        }

        if modifiers.ctrl
            && (vk_code == u32::from(VK_C.0)
                || vk_code == u32::from(VK_V.0)
                || vk_code == u32::from(VK_X.0)
                || vk_code == u32::from(VK_INSERT.0))
        {
            return true;
        }

        if modifiers.shift && vk_code == u32::from(VK_INSERT.0) {
            return true;
        }

        false
    }

    fn should_block_shortcut_with_modifiers(vk_code: u32, modifiers: KeyModifiers) -> bool {
        should_block_shortcut_with_policy(vk_code, modifiers, is_developer_escape_enabled())
    }

    fn should_block_shortcut(vk_code: u32) -> bool {
        should_block_shortcut_with_modifiers(vk_code, current_modifiers())
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
        ready_tx: mpsc::Sender<Result<u32, String>>,
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

            let mut bootstrap_message = MSG::default();
            unsafe {
                let _ = PeekMessageW(&mut bootstrap_message, None, 0, 0, PM_NOREMOVE);
            }

            let thread_id = unsafe { GetCurrentThreadId() };
            INPUT_GUARD_ACTIVE.store(true, Ordering::SeqCst);
            let _ = ready_tx.send(Ok(thread_id));

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

    fn stop_input_guard(handle: InputGuardHandle) {
        handle.stop_flag.store(true, Ordering::SeqCst);
        INPUT_GUARD_ACTIVE.store(false, Ordering::SeqCst);
        unsafe {
            let _ = PostThreadMessageW(handle.thread_id, WM_QUIT, WPARAM(0), LPARAM(0));
        }
        let _ = handle.thread.join();
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

        if let Some(existing_handle) = guard.as_ref() {
            if is_thread_guard_healthy(
                true,
                INPUT_GUARD_ACTIVE.load(Ordering::SeqCst),
                existing_handle.thread.is_finished(),
            ) {
                return InputGuardMutationResult {
                    applied: true,
                    active: true,
                    detail: "Native keyboard hook is already active.".to_string(),
                };
            }
        }

        if let Some(stale_handle) = guard.take() {
            stop_input_guard(stale_handle);
        }

        let stop_flag = Arc::new(AtomicBool::new(false));
        let (ready_tx, ready_rx) = mpsc::channel();
        let thread = spawn_input_guard_thread(Arc::clone(&stop_flag), ready_tx);

        match ready_rx.recv_timeout(Duration::from_secs(3)) {
            Ok(Ok(thread_id)) => {
                *guard = Some(InputGuardHandle {
                    stop_flag,
                    thread_id,
                    thread,
                });
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
            stop_input_guard(handle);

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

    #[cfg(test)]
    mod tests {
        use super::{
            should_block_shortcut_with_modifiers, should_block_shortcut_with_policy, KeyModifiers,
            VK_C, VK_F12, VK_INSERT, VK_S, VK_SNAPSHOT, VK_TAB, VK_V, VK_X,
        };

        #[test]
        fn blocks_print_screen_without_modifiers() {
            assert!(should_block_shortcut_with_modifiers(
                u32::from(VK_SNAPSHOT.0),
                KeyModifiers::default(),
            ));
        }

        #[test]
        fn blocks_windows_snipping_shortcut() {
            assert!(should_block_shortcut_with_modifiers(
                u32::from(VK_S.0),
                KeyModifiers {
                    win: true,
                    shift: true,
                    ..KeyModifiers::default()
                },
            ));
        }

        #[test]
        fn blocks_alt_tab_but_keeps_plain_tab() {
            assert!(should_block_shortcut_with_modifiers(
                u32::from(VK_TAB.0),
                KeyModifiers {
                    alt: true,
                    ..KeyModifiers::default()
                },
            ));
            assert!(!should_block_shortcut_with_modifiers(
                u32::from(VK_TAB.0),
                KeyModifiers::default(),
            ));
        }

        #[test]
        fn blocks_developer_escape_by_default() {
            assert!(should_block_shortcut_with_policy(
                u32::from(VK_F12.0),
                KeyModifiers {
                    ctrl: true,
                    shift: true,
                    ..KeyModifiers::default()
                },
                false,
            ));
        }

        #[test]
        fn allows_developer_escape_only_when_explicitly_enabled() {
            assert!(!should_block_shortcut_with_policy(
                u32::from(VK_F12.0),
                KeyModifiers {
                    ctrl: true,
                    shift: true,
                    ..KeyModifiers::default()
                },
                true,
            ));
        }

        #[test]
        fn blocks_clipboard_keyboard_shortcuts() {
            let ctrl = KeyModifiers {
                ctrl: true,
                ..KeyModifiers::default()
            };

            assert!(should_block_shortcut_with_modifiers(u32::from(VK_C.0), ctrl));
            assert!(should_block_shortcut_with_modifiers(u32::from(VK_V.0), ctrl));
            assert!(should_block_shortcut_with_modifiers(u32::from(VK_X.0), ctrl));
            assert!(should_block_shortcut_with_modifiers(
                u32::from(VK_INSERT.0),
                ctrl,
            ));
            assert!(should_block_shortcut_with_modifiers(
                u32::from(VK_INSERT.0),
                KeyModifiers {
                    shift: true,
                    ..KeyModifiers::default()
                },
            ));
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
