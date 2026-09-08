//! Versioned ALSA sample-clock evidence; PCM and session times are distinct domains.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureClock {
    pub schema: String,
    pub clock: String,
    pub timestamp_source: String,
    pub continuity: String,
    pub device: String,
    pub period_frames: u64,
    pub buffer_frames: u64,
    pub thread_started_monotonic_ns: u64,
    pub thread_stopped_monotonic_ns: u64,
    pub sample_start_monotonic_ns: u64,
    pub sample_end_monotonic_ns: u64,
    pub session_start_monotonic_ns: u64,
    pub max_residual_ns: u64,
    pub anchors: Vec<[u64; 2]>,
    pub queue_capacity_frames: u64,
    pub queue_peak_frames: u64,
    pub max_write_ns: u64,
    pub xrun_count: u64,
    pub suspend_count: u64,
}

impl CaptureClock {
    pub fn validate(
        &self,
        rate: u64,
        count: u64,
        start: f64,
        end: f64,
        duration: f64,
    ) -> Result<(), String> {
        if self.schema != "openaria.audio-clock.v1"
            || self.clock != "host_monotonic"
            || self.timestamp_source != "alsa_htimestamp_dma"
            || self.continuity != "verified"
            || self.device.is_empty()
            || rate == 0
            || count == 0
            || !start.is_finite()
            || !end.is_finite()
            || !duration.is_finite()
            || start < 0.0
            || end <= start
            || end > duration + 1e-6
            || self.xrun_count != 0
            || self.suspend_count != 0
            || self.period_frames == 0
            || self.period_frames > self.buffer_frames
            || self.queue_peak_frames == 0
            || self.queue_peak_frames > self.queue_capacity_frames
            || self.max_residual_ns > 20_000_000
            || self.anchors.len() < 2
            || self.anchors.iter().any(|a| a[0] == 0 || a[1] == 0)
            || self
                .anchors
                .windows(2)
                .any(|p| p[1][0] <= p[0][0] || p[1][1] <= p[0][1])
        {
            return Err("invalid audio capture-clock evidence".into());
        }
        let first = self.anchors[0];
        let last = self.anchors[self.anchors.len() - 1];
        let tick = (last[1] - first[1]) as f64 / (last[0] - first[0]) as f64;
        let residual = self
            .anchors
            .iter()
            .map(|a| ((a[1] - first[1]) as f64 - (a[0] - first[0]) as f64 * tick).abs())
            .fold(0.0_f64, f64::max);
        let predicted_start = first[1] as f64 - first[0] as f64 * tick;
        let predicted_end = predicted_start + count as f64 * tick;
        let origin = self.session_start_monotonic_ns as f64;
        if (1e9 / tick / rate as f64 - 1.0).abs() > 0.01
            || (residual - self.max_residual_ns as f64).abs() > 2.0
            || (predicted_start - self.sample_start_monotonic_ns as f64).abs() > 2.0
            || (predicted_end - self.sample_end_monotonic_ns as f64).abs() > 2.0
            || (start * 1e9 - (self.sample_start_monotonic_ns as f64 - origin)).abs() > 2.0
            || (end * 1e9 - (self.sample_end_monotonic_ns as f64 - origin)).abs() > 2.0
            || self.thread_started_monotonic_ns < self.session_start_monotonic_ns
            || self.thread_stopped_monotonic_ns <= self.thread_started_monotonic_ns
            || predicted_start < self.thread_started_monotonic_ns as f64 - 20_000_000.0
            || predicted_end > self.thread_stopped_monotonic_ns as f64 + 20_000_000.0
            || self.thread_stopped_monotonic_ns as f64 - origin > duration * 1e9 + 1000.0
            || first[0] > self.buffer_frames.saturating_add(self.period_frames)
            || last[0] < count
            || last[0] > count.saturating_add(self.buffer_frames)
            || self
                .anchors
                .windows(2)
                .any(|p| p[1][0] - p[0][0] > rate.saturating_add(self.buffer_frames))
        {
            return Err("audio sync does not match sample-clock evidence".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> CaptureClock {
        serde_json::from_value(serde_json::json!({
            "schema":"openaria.audio-clock.v1", "clock":"host_monotonic",
            "timestamp_source":"alsa_htimestamp_dma", "continuity":"verified",
            "device":"hw:CARD=D2UQ2,DEV=0", "period_frames":1024, "buffer_frames":8192,
            "thread_started_monotonic_ns":1100000000u64, "thread_stopped_monotonic_ns":3110000000u64,
            "sample_start_monotonic_ns":1100000000u64, "sample_end_monotonic_ns":3100000000u64,
            "session_start_monotonic_ns":1000000000u64, "max_residual_ns":0,
            "anchors":[[1024u64,1202400000u64],[11024u64,2202400000u64],[20000u64,3100000000u64]],
            "queue_capacity_frames":262144, "queue_peak_frames":1024, "max_write_ns":500000,
            "xrun_count":0,"suspend_count":0
        })).unwrap()
    }
    #[test]
    fn validates_measured_clock_and_rejects_tampering() {
        let clock = fixture();
        assert!(clock.validate(10000, 20000, 0.1, 2.1, 3.0).is_ok());
        assert!(clock.validate(10000, 20000, 0.1, 1.1, 3.0).is_err());
        assert!(clock.validate(10000, 21000, 0.1, 2.1, 3.0).is_err());
        let mut broken = clock.clone();
        broken.anchors[1][1] += 50_000_000;
        assert!(broken.validate(10000, 20000, 0.1, 2.1, 3.0).is_err());
        broken = clock;
        broken.xrun_count = 1;
        assert!(broken.validate(10000, 20000, 0.1, 2.1, 3.0).is_err());
    }
}
