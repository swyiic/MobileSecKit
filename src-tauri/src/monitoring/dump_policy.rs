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
    fn contradictory_policy_is_rejected() {
        assert!(dump_launch_flag(false, true, false).is_err());
        assert!(dump_launch_flag(false, true, true).is_err());
    }
}
