//! F-018 — RAII wrappers for Win32 resources.
//!
//! Manual `CloseHandle`/`LocalFree` on every branch is a handle-leak / double-free
//! hazard (the audit flagged un-audited `unsafe` FFI). These guards make the
//! "who releases this, on which path?" answer structural: the resource is freed
//! exactly once, on drop, including on early-return and error paths.

/// Owns a Win32 `HANDLE` and closes it on drop.
///
/// Construct via [`OwnedHandle::new`], which rejects null / `INVALID_HANDLE_VALUE`
/// so a failed `OpenProcess` never produces a guard that would `CloseHandle(-1)`.
/// Pseudo-handles (e.g. `GetCurrentProcess()` == -1) are intentionally rejected —
/// they must not be closed.
#[cfg(target_os = "windows")]
pub struct OwnedHandle(windows::Win32::Foundation::HANDLE);

#[cfg(target_os = "windows")]
impl OwnedHandle {
    /// # Safety
    /// `handle` must be a real, owned handle (e.g. from `OpenProcess`) that is
    /// valid to `CloseHandle` exactly once and is not used after this guard drops.
    pub unsafe fn new(handle: windows::Win32::Foundation::HANDLE) -> Option<Self> {
        if handle.is_invalid() {
            None
        } else {
            Some(Self(handle))
        }
    }

    pub fn get(&self) -> windows::Win32::Foundation::HANDLE {
        self.0
    }
}

#[cfg(target_os = "windows")]
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: constructed only from a valid, owned handle (see `new`), closed
        // exactly once here.
        let _ = unsafe { windows::Win32::Foundation::CloseHandle(self.0) };
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "windows")]
    #[test]
    fn rejects_invalid_handles() {
        use windows::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
        // Null and INVALID_HANDLE_VALUE are rejected -> no CloseHandle on drop.
        assert!(unsafe { super::OwnedHandle::new(HANDLE::default()) }.is_none());
        assert!(unsafe { super::OwnedHandle::new(INVALID_HANDLE_VALUE) }.is_none());
    }
}
