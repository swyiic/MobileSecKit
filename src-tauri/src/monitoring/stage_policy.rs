//! Pure desktop validation for the opt-in device stage contract.
pub(super) fn validate_stages(text: &str, duration: u64) -> Result<(), String> {
    let mut names = Vec::new();
    let mut total = 0;
    for item in text.split(',') {
        let (name, seconds) = item
            .split_once(':')
            .ok_or("阶段格式必须为 l0:秒,l1:秒,linker:秒")?;
        if !matches!(name, "l0" | "l1" | "linker") || names.contains(&name) {
            return Err("阶段未知或重复".into());
        }
        let seconds: u64 = seconds.parse().map_err(|_| "阶段时长无效")?;
        if !(1..=300).contains(&seconds) {
            return Err("每阶段须为 1–300 秒".into());
        }
        names.push(name);
        total += seconds;
    }
    if names.is_empty() || names.len() > 3 || names.iter().all(|n| *n == "l0") || total != duration
    {
        return Err("阶段总时长或 Inspect 能力无效".into());
    }
    Ok(())
}
pub(super) fn validate_mode(
    text: Option<&str>,
    duration: u64,
    package_present: bool,
    mixed_flags: bool,
) -> Result<(), String> {
    if let Some(text) = text {
        validate_stages(text, duration)?;
        if !package_present || mixed_flags {
            return Err("统一阶段必须指定包，不能叠加单阶段 Inspect/mirror".into());
        }
    } else if !(1..=300).contains(&duration) {
        return Err("旧模式采集时长必须在 1–300 秒之间".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stages_have_exact_total_and_safe_tokens() {
        assert!(validate_stages("l0:15,l1:90,linker:15", 120).is_ok());
        assert!(validate_stages("linker:300,l1:300,l0:300", 900).is_ok());
        for (s, d) in [
            ("l0:1", 1),
            ("l1:0", 0),
            ("l1:301", 301),
            ("l1:1,l1:2", 3),
            ("l1:1;cmd", 1),
            ("l1:1", 2),
        ] {
            assert!(validate_stages(s, d).is_err(), "{s}");
        }
    }
    #[test]
    fn legacy_duration_and_new_mixed_flag_contracts_are_explicit() {
        assert!(validate_mode(None, 300, false, false).is_ok());
        assert!(validate_mode(None, 301, true, false).is_err());
        assert!(validate_mode(Some("l1:300,linker:300"), 600, true, false).is_ok());
        assert!(validate_mode(Some("l1:1"), 1, false, false).is_err());
        assert!(validate_mode(Some("l1:1"), 1, true, true).is_err());
    }
}
