//! Keep warm-run evidence separate from an explicitly requested fresh launch.

pub(super) fn live_pid_confirmed(code: Option<i32>, stdout: &str) -> bool {
    if code != Some(0) {
        return false;
    }
    let mut tokens = stdout.split_whitespace().peekable();
    tokens.peek().is_some() && tokens.all(|text| text.parse::<u32>().is_ok_and(|pid| pid > 0))
}

pub(super) fn dump_launch_flag(
    prefer_live: bool,
    require_live: bool,
    live_confirmed: bool,
) -> Result<&'static str, String> {
    if require_live && !prefer_live {
        return Err("连续采集的最终快照必须先确认运行中的目标".into());
    }
    if require_live && !live_confirmed {
        return Err("无法确认目标主进程仍在运行，连续采集停止；不自动重新冷启动，已有会话和证据保留。请核对进程、权限及设备连接后再采集".into());
    }
    Ok(if prefer_live && live_confirmed {
        ""
    } else {
        " --launch"
    })
}

/// Charge preflight to the original grant and leave time for producer return and
/// the remote lifecycle observation. Exhaustion refuses launch; it never renews.
pub(super) fn producer_time_ms(grant_ms: u64, preflight_ms: u64) -> Result<u64, String> {
    grant_ms
        .checked_sub(preflight_ms)
        .and_then(|remaining| remaining.checked_sub(10_000))
        .filter(|remaining| *remaining > 0)
        .ok_or_else(|| {
            "phase_time_holdback_exhausted: Dump preflight/terminal reserve; not started".into()
        })
}

/// A fixed v5 scope already spent preflight on the original absolute clock.
/// Legacy callers still supply the original numeric grant and must deduct it.
pub(super) fn producer_time_for_scope(
    remaining_ms: u64,
    preflight_ms: u64,
    fixed_scope: bool,
) -> Result<u64, String> {
    producer_time_ms(remaining_ms, if fixed_scope { 0 } else { preflight_ms })
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_or_ambiguous_pid_probe_is_not_live_evidence() {
        assert!(live_pid_confirmed(Some(0), "42 73\n"));
        for (code, text) in [
            (Some(0), ""),
            (Some(1), "42"),
            (None, "42"),
            (Some(0), "0"),
            (Some(0), "-1"),
            (Some(0), "warning 42"),
        ] {
            assert!(!live_pid_confirmed(code, text));
        }
    }

    #[test]
    fn required_live_snapshot_never_falls_back_to_launch() {
        assert!(dump_launch_flag(true, true, false).is_err());
        assert_eq!(dump_launch_flag(true, true, true).unwrap(), "");
    }

    #[test]
    fn old_optional_live_and_explicit_launch_contracts_remain_compatible() {
        assert_eq!(dump_launch_flag(true, false, true).unwrap(), "");
        assert_eq!(dump_launch_flag(true, false, false).unwrap(), " --launch");
        assert_eq!(dump_launch_flag(false, false, false).unwrap(), " --launch");
        assert_eq!(dump_launch_flag(false, false, true).unwrap(), " --launch");
    }

    #[test]
    fn producer_grant_charges_preflight_and_preserves_terminal_reserve() {
        assert_eq!(producer_time_ms(95_000, 2_000).unwrap(), 83_000);
        // Real UI Dump ran 63.042s: the old 55s lease must still fail;
        // a new 95s lease admits that duration before its original boundary.
        assert!(producer_time_ms(95_000, 2_000).unwrap() > 63_042);
        for elapsed in [85_000, 95_000, u64::MAX] {
            assert!(producer_time_ms(95_000, elapsed).is_err());
        }
    }

    #[test]
    fn manual_time_v5_fixed_scope_spends_preflight_once() {
        assert_eq!(
            producer_time_for_scope(241_000, 4_000, true).unwrap(),
            231_000
        );
        assert_eq!(
            producer_time_for_scope(245_000, 4_000, false).unwrap(),
            231_000
        );
        assert!(producer_time_for_scope(10_000, 0, true).is_err());
    }
    #[test]
    fn contradictory_policy_is_rejected() {
        assert!(dump_launch_flag(false, true, false).is_err());
        assert!(dump_launch_flag(false, true, true).is_err());
    }
}
