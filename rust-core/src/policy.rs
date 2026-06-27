use crate::models::PrecheckSnapshot;

#[derive(Debug, Clone)]
pub struct PrecheckPolicy {
    pub policy_version: String,
    pub review_threshold: u32,
    pub block_threshold: u32,
    pub max_monitor_count: usize,
    pub allow_continue_on_review: bool,
    pub allow_remote_processes: bool,
    pub allow_screen_capture_processes: bool,
    pub allow_debug_tools: bool,
}

impl Default for PrecheckPolicy {
    fn default() -> Self {
        Self {
            policy_version: "phase5-advisory-v1".to_string(),
            review_threshold: 25,
            block_threshold: 80,
            max_monitor_count: 1,
            allow_continue_on_review: true,
            allow_remote_processes: false,
            allow_screen_capture_processes: false,
            allow_debug_tools: false,
        }
    }
}

impl PrecheckPolicy {
    pub fn for_snapshot(_snapshot: &PrecheckSnapshot) -> Self {
        // Phase 5 still uses a local policy so the engine stays deterministic while
        // the backend policy endpoint is not connected yet.
        //
        // At this stage the gate is advisory-first:
        // the user should see warnings before entering the room, but secure
        // session protection is enforced later when the real exam session starts.
        Self::default()
    }
}
