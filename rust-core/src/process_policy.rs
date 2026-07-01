use crate::policy_model::{list_contains, ExamPolicy};

pub const CATEGORY_BROWSER: &str = "browser";
pub const CATEGORY_COMMUNICATION: &str = "communication";
pub const CATEGORY_POLICY_BLOCKED: &str = "policyBlocked";
pub const CATEGORY_REMOTE_DESKTOP: &str = "remoteDesktop";
pub const CATEGORY_SCREEN_CAPTURE: &str = "screenCapture";
pub const CATEGORY_VIRTUAL_MACHINE: &str = "virtualMachine";
pub const CATEGORY_DEBUG_TOOLS: &str = "debugTools";

#[cfg(test)]
pub fn categorize_process_name(name: &str) -> Vec<String> {
    categorize_process_name_with_policy(name, &ExamPolicy::strict_builtin())
}

pub fn categorize_process_name_with_policy(name: &str, policy: &ExamPolicy) -> Vec<String> {
    let normalized = name.trim().to_ascii_lowercase();
    let mut categories = Vec::new();

    if policy.is_explicitly_blocked(&normalized) {
        categories.push(CATEGORY_POLICY_BLOCKED.to_string());
    }
    push_category_if_matches(
        &mut categories,
        &normalized,
        &policy.browser_processes,
        CATEGORY_BROWSER,
    );
    push_category_if_matches(
        &mut categories,
        &normalized,
        &policy.communication_processes,
        CATEGORY_COMMUNICATION,
    );
    push_category_if_matches(
        &mut categories,
        &normalized,
        &policy.remote_processes,
        CATEGORY_REMOTE_DESKTOP,
    );
    push_category_if_matches(
        &mut categories,
        &normalized,
        &policy.screen_capture_processes,
        CATEGORY_SCREEN_CAPTURE,
    );
    push_category_if_matches(
        &mut categories,
        &normalized,
        &policy.virtual_machine_processes,
        CATEGORY_VIRTUAL_MACHINE,
    );
    push_category_if_matches(
        &mut categories,
        &normalized,
        &policy.debug_processes,
        CATEGORY_DEBUG_TOOLS,
    );

    categories
}

pub fn is_process_prohibited(name: &str, policy: &ExamPolicy) -> bool {
    if policy.is_explicitly_allowed(name) {
        return false;
    }
    policy.is_explicitly_blocked(name)
        || list_contains(&policy.remote_processes, name)
        || list_contains(&policy.screen_capture_processes, name)
        || list_contains(&policy.debug_processes, name)
        || (!policy.allow_vm && list_contains(&policy.virtual_machine_processes, name))
}

pub fn contains_vm_vendor(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    normalized.contains("vmware")
        || normalized.contains("virtualbox")
        || normalized.contains("virtual box")
        || normalized.contains("hyper-v")
        || normalized.contains("kvm")
        || normalized.contains("qemu")
        || normalized.contains("parallels")
}

fn push_category_if_matches(
    categories: &mut Vec<String>,
    executable_name: &str,
    prohibited_names: &[String],
    category: &str,
) {
    if prohibited_names
        .iter()
        .any(|candidate| executable_name == candidate)
    {
        categories.push(category.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::{
        categorize_process_name, categorize_process_name_with_policy, contains_vm_vendor,
        is_process_prohibited, CATEGORY_COMMUNICATION,
        CATEGORY_REMOTE_DESKTOP, CATEGORY_SCREEN_CAPTURE,
    };

    #[test]
    fn classification_is_case_insensitive_and_supports_multiple_categories() {
        let categories = categorize_process_name("Discord.EXE");

        assert!(categories.iter().any(|entry| entry == CATEGORY_COMMUNICATION));
        assert!(categories.iter().any(|entry| entry == CATEGORY_SCREEN_CAPTURE));
    }

    #[test]
    fn classifier_requires_an_exact_executable_name() {
        assert!(categorize_process_name("myobs.exe").is_empty());
        assert!(categorize_process_name("anydesk.exe.backup").is_empty());
        assert!(categorize_process_name("AnyDesk.exe")
            .iter()
            .any(|entry| entry == CATEGORY_REMOTE_DESKTOP));
    }

    #[test]
    fn detects_known_virtual_machine_vendors() {
        assert!(contains_vm_vendor("VMware, Inc."));
        assert!(contains_vm_vendor("Virtual Box"));
        assert!(!contains_vm_vendor("Dell Inc."));
    }

    #[test]
    fn classifies_added_remote_and_capture_tools() {
        for name in ["ultraviewer.exe", "aweray_remote.exe", "msrdc.exe"] {
            assert!(categorize_process_name(name)
                .iter()
                .any(|entry| entry == CATEGORY_REMOTE_DESKTOP));
        }

        for name in [
            "lightshot.exe",
            "greenshot.exe",
            "flameshot.exe",
            "kazam.exe",
        ] {
            assert!(categorize_process_name(name)
                .iter()
                .any(|entry| entry == CATEGORY_SCREEN_CAPTURE));
        }
    }

    #[test]
    fn signed_policy_can_replace_categories_and_allow_an_exception() {
        let mut policy = crate::policy_model::ExamPolicy::strict_builtin();
        policy.remote_processes = vec!["custom-remote.exe".to_string()];
        policy.allowed_processes = vec!["custom-remote.exe".to_string()];

        assert!(categorize_process_name_with_policy("AnyDesk.exe", &policy).is_empty());
        assert!(categorize_process_name_with_policy("custom-remote.exe", &policy)
            .iter()
            .any(|entry| entry == CATEGORY_REMOTE_DESKTOP));
        assert!(!is_process_prohibited("custom-remote.exe", &policy));
    }
}
