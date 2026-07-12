//! Shared time-range containment check.
//!
//! The Sigstore trust materials (trusted root `validFor` windows and signing
//! config service validity periods) are all instances of the protobuf-specs
//! `TimeRange` message, whose documented semantics are:
//!
//! > The time range is closed and includes both the start and end times,
//! > (i.e., `[start, end]`).
//! > End is optional to be able to capture a period that has started but
//! > has no known end.
//!
//! Every validity check in this crate goes through [`time_range_contains`]
//! so the semantics cannot drift between representations.

use jiff::Timestamp;

/// Whether `time` falls within the closed interval `[start, end]`.
///
/// A missing `end` means the period has started but has no known end, i.e.
/// it is unbounded on that side. `start` is required by the specification
/// and therefore not optional here; callers translate a missing start into
/// an error before reaching this check.
pub(crate) fn time_range_contains(
    start: Timestamp,
    end: Option<Timestamp>,
    time: Timestamp,
) -> bool {
    time >= start && end.map_or(true, |e| time <= e)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    #[test]
    fn range_is_closed_on_both_ends() {
        let start = ts("2020-01-01T00:00:00Z");
        let end_ts = ts("2021-01-01T00:00:00Z");
        let end = Some(end_ts);

        // Boundaries are included
        assert!(time_range_contains(start, end, start));
        assert!(time_range_contains(start, end, end_ts));

        assert!(time_range_contains(start, end, ts("2020-06-01T00:00:00Z")));
        assert!(!time_range_contains(start, end, ts("2019-12-31T23:59:59Z")));
        assert!(!time_range_contains(start, end, ts("2021-01-01T00:00:01Z")));
    }

    #[test]
    fn missing_end_is_unbounded() {
        let start = ts("2020-01-01T00:00:00Z");
        assert!(time_range_contains(start, None, ts("2999-01-01T00:00:00Z")));
        assert!(!time_range_contains(
            start,
            None,
            ts("2019-01-01T00:00:00Z")
        ));
    }
}
