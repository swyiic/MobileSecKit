//! Aggregate retained kernel perf-loss notifications without inventing attribution.
use ksight_model::{Event, EventPayload};
use serde_json::{json, Value};

#[derive(Default)]
pub(super) struct PerfLoss {
    reported: u64,
    additional: u64,
    notifications: u64,
    after_stop: u64,
}
impl PerfLoss {
    pub(super) fn record(&mut self, event: &Event) {
        let EventPayload::InspectObservation(row) = &event.payload else {
            return;
        };
        if row.hit || row.attached {
            return;
        }
        self.record_detail(&row.detail, event.header.quality.lost_before);
    }
    fn record_detail(&mut self, detail: &str, header_lost: u64) {
        if detail.len() > 2048 {
            return;
        }
        let Ok(note) = serde_json::from_str::<Value>(detail) else {
            return;
        };
        if note["schema"] != "kernsight.perf-loss/v1"
            || note["cpu_id"]
                .as_u64()
                .is_none_or(|cpu| cpu > u32::MAX as u64)
            || note["notification_monotonic_ns"].as_u64().is_none()
            || note["lost_event_time_unknown"] != true
        {
            return;
        }
        let (Some(lost), Some(after_stop)) = (
            note["lost_samples"].as_u64(),
            note["after_producer_stop"].as_bool(),
        ) else {
            return;
        };
        self.reported = self.reported.saturating_add(lost);
        // A newer producer may already count the same notification in its header.
        self.additional = self
            .additional
            .saturating_add(lost.saturating_sub(header_lost));
        self.notifications = self.notifications.saturating_add(1);
        if after_stop {
            self.after_stop = self.after_stop.saturating_add(lost);
        }
    }
    pub(super) fn augment(&self, report: &mut Value) {
        if self.notifications == 0 {
            return;
        }
        let original = report["quality"]["lost_records"].as_u64().unwrap_or(0);
        report["quality"]["lost_records"] = json!(original.saturating_add(self.additional));
        if self.additional > 0 {
            report["quality"]["lost_by_sensor"]["inspect_perf_unattributed"] =
                json!(self.additional);
        }
        report["mobilee_perf_loss"] = json!({
            "schema":"mobilee.retained-perf-loss/v1",
            "source":"original kernsight.perf-loss/v1 InspectObservation detail",
            "reported_kernel_lost_samples":self.reported,
            "additional_to_header_quality":self.additional,
            "header_quality_lost_records":original,
            "notification_count":self.notifications,
            "reported_after_producer_stop":self.after_stop,
            "lost_event_target":"unknown", "lost_event_time":"unknown",
            "collection_coverage":"partial; retained events remain analyzable"
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn notice(lost: u64, after: bool) -> String {
        json!({"schema":"kernsight.perf-loss/v1","cpu_id":6,"notification_monotonic_ns":42,
            "lost_event_time_unknown":true,"lost_samples":lost,"after_producer_stop":after})
        .to_string()
    }
    #[test]
    fn retained_notifications_fill_old_report_without_double_counting_new_headers() {
        let mut loss = PerfLoss::default();
        loss.record_detail(&notice(223, false), 0);
        loss.record_detail(&notice(127, true), 127);
        let mut report = json!({"quality":{"lost_records":130,"lost_by_sensor":{"other":3}},"execution_complete":false});
        loss.augment(&mut report);
        assert_eq!(report["quality"]["lost_records"], 353);
        assert_eq!(
            report["mobilee_perf_loss"]["reported_kernel_lost_samples"],
            350
        );
        assert_eq!(
            report["mobilee_perf_loss"]["reported_after_producer_stop"],
            127
        );
        assert_eq!(report["execution_complete"], false);
    }
    #[test]
    fn malformed_or_unrecognized_detail_does_not_invent_zero_loss_receipt() {
        let mut loss = PerfLoss::default();
        for detail in [
            "bad json",
            "{}",
            "{\"schema\":\"other\",\"lost_samples\":90}",
        ] {
            loss.record_detail(detail, 0);
        }
        let mut report = json!({"quality":{"lost_records":2}});
        loss.augment(&mut report);
        assert_eq!(report, json!({"quality":{"lost_records":2}}));
    }
}
