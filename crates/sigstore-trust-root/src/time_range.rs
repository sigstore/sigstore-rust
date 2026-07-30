//! The protobuf-specs `TimeRange` message.
//!
//! Every validity window in the Sigstore trust materials — the trusted root's
//! `validFor` fields and the signing config's service validity periods — is an
//! instance of the same protobuf-specs `TimeRange` message, so they share this
//! one type rather than each carrying their own interpretation of it.

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

/// A validity window, i.e. the protobuf-specs `TimeRange` message:
///
/// > The time range is closed and includes both the start and end times,
/// > (i.e., `[start, end]`).
/// > End is optional to be able to capture a period that has started but
/// > has no known end.
///
/// `start` is required by the specification and therefore required here: a
/// `validFor` object without a start time fails to parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimeRange {
    /// Start of the window (inclusive).
    pub start: Timestamp,

    /// End of the window (inclusive). `None` means the period has started but
    /// has no known end.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<Timestamp>,
}

impl TimeRange {
    /// Create a time range from its bounds.
    pub fn new(start: Timestamp, end: Option<Timestamp>) -> Self {
        Self { start, end }
    }

    /// Whether `time` falls within the closed interval `[start, end]`.
    ///
    /// A missing `end` is unbounded on that side.
    pub fn contains(&self, time: Timestamp) -> bool {
        time >= self.start && self.end.map_or(true, |end| time <= end)
    }

    /// Whether this window had started by `time` (i.e. `start <= time`),
    /// ignoring its end.
    ///
    /// Instances that have started — including ones whose window has since
    /// expired — are still required to verify historical material that was
    /// produced while they were valid.
    pub fn has_started_by(&self, time: Timestamp) -> bool {
        time >= self.start
    }

    /// Whether this window contains the current time.
    pub fn is_valid(&self) -> bool {
        self.contains(Timestamp::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    fn range(start: &str, end: Option<&str>) -> TimeRange {
        TimeRange::new(ts(start), end.map(ts))
    }

    #[test]
    fn range_is_closed_on_both_ends() {
        let r = range("2020-01-01T00:00:00Z", Some("2021-01-01T00:00:00Z"));

        // Boundaries are included
        assert!(r.contains(r.start));
        assert!(r.contains(r.end.unwrap()));

        assert!(r.contains(ts("2020-06-01T00:00:00Z")));
        assert!(!r.contains(ts("2019-12-31T23:59:59Z")));
        assert!(!r.contains(ts("2021-01-01T00:00:01Z")));
    }

    #[test]
    fn missing_end_is_unbounded() {
        let r = range("2020-01-01T00:00:00Z", None);
        assert!(r.contains(ts("2999-01-01T00:00:00Z")));
        assert!(!r.contains(ts("2019-01-01T00:00:00Z")));
    }

    #[test]
    fn has_started_by_ignores_the_end_bound() {
        let r = range("2020-01-01T00:00:00Z", Some("2021-01-01T00:00:00Z"));
        assert!(r.has_started_by(ts("2020-06-01T00:00:00Z")));
        // Expired, but started
        assert!(r.has_started_by(ts("2022-06-01T00:00:00Z")));
        assert!(!r.has_started_by(ts("2019-06-01T00:00:00Z")));
    }

    #[test]
    fn start_is_required_by_the_specification() {
        assert!(serde_json::from_str::<TimeRange>(r#"{"start": "2020-01-01T00:00:00Z"}"#).is_ok());
        assert!(serde_json::from_str::<TimeRange>(r#"{"end": "2020-01-01T00:00:00Z"}"#).is_err());
    }

    #[test]
    fn fractional_second_timestamps_parse() {
        let r: TimeRange = serde_json::from_str(
            r#"{"start": "2021-01-12T11:53:27.000Z", "end": "2022-04-13T20:06:15.000Z"}"#,
        )
        .unwrap();
        assert_eq!(r.start, ts("2021-01-12T11:53:27Z"));
        assert_eq!(r.end, Some(ts("2022-04-13T20:06:15Z")));
    }
}
