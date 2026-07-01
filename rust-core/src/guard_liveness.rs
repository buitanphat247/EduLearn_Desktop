pub fn is_thread_guard_healthy(
    handle_present: bool,
    active_signal: bool,
    thread_finished: bool,
) -> bool {
    handle_present && active_signal && !thread_finished
}

#[cfg(test)]
mod tests {
    use super::is_thread_guard_healthy;

    #[test]
    fn requires_handle_active_signal_and_live_thread() {
        assert!(is_thread_guard_healthy(true, true, false));
        assert!(!is_thread_guard_healthy(false, true, false));
        assert!(!is_thread_guard_healthy(true, false, false));
        assert!(!is_thread_guard_healthy(true, true, true));
    }
}
