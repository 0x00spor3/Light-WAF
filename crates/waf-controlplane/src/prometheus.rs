// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! Minimal parser for the OPEN `/metrics` text exposition. We only need what the control plane
//! stores as rollups: the `waf_requests_total{decision="…"}` counters. Hand-rolled (the format is
//! our own, simple, and controlled) — no client-library dependency. Latency histogram buckets are
//! parsed/stored in Phase 3, when the read API serves them.

/// One scraped `waf_requests_total` sample: the decision label and its counter value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionCount {
    pub decision: String,
    pub count: i64,
}

/// One `waf_request_duration_seconds_bucket{le}` sample: the bucket upper bound (seconds; `+Inf`
/// → `f64::INFINITY`) and its cumulative count.
#[derive(Debug, Clone, PartialEq)]
pub struct LatencyBucket {
    pub le: f64,
    pub count: i64,
}

/// Extract every `waf_requests_total{decision="X"} N` sample from a `/metrics` body. Comment lines
/// (`#`), blank lines and unrelated metrics are ignored; a malformed sample is skipped (a scrape
/// must never fail the whole batch on one odd line).
pub fn parse_requests_total(text: &str) -> Vec<DecisionCount> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(rest) = line.strip_prefix("waf_requests_total{") else {
            continue;
        };
        // rest = `decision="X",…} N` — split the label block from the trailing value.
        let Some((labels, value)) = rest.split_once('}') else {
            continue;
        };
        let Some(decision) = label_value(labels, "decision") else {
            continue;
        };
        let Ok(count) = value.trim().parse::<i64>() else {
            continue;
        };
        out.push(DecisionCount { decision, count });
    }
    out
}

/// Extract the `waf_request_duration_seconds_bucket{le="X"} N` histogram, sorted by `le`
/// ascending (`+Inf` last). Malformed samples are skipped.
pub fn parse_latency_buckets(text: &str) -> Vec<LatencyBucket> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(rest) = line.strip_prefix("waf_request_duration_seconds_bucket{") else {
            continue;
        };
        let Some((labels, value)) = rest.split_once('}') else {
            continue;
        };
        let Some(le_str) = label_value(labels, "le") else {
            continue;
        };
        let le = if le_str == "+Inf" { f64::INFINITY } else { le_str.parse::<f64>().ok().unwrap_or(f64::NAN) };
        let Ok(count) = value.trim().parse::<i64>() else {
            continue;
        };
        if !le.is_nan() {
            out.push(LatencyBucket { le, count });
        }
    }
    out.sort_by(|a, b| a.le.partial_cmp(&b.le).unwrap_or(std::cmp::Ordering::Equal));
    out
}

/// Prometheus-style `histogram_quantile` over cumulative buckets sorted by `le`. `q ∈ [0,1]`.
/// Returns the interpolated latency (seconds), or `None` if the histogram is empty/degenerate.
/// Linear interpolation within the bucket the target rank falls in (the `+Inf` bound clamps to the
/// previous finite bound, as Prometheus does).
pub fn histogram_quantile(buckets: &[LatencyBucket], q: f64) -> Option<f64> {
    let total = buckets.last()?.count as f64;
    if total <= 0.0 {
        return None;
    }
    let rank = q.clamp(0.0, 1.0) * total;
    let mut prev_le = 0.0_f64;
    let mut prev_count = 0.0_f64;
    for b in buckets {
        let count = b.count as f64;
        if count >= rank {
            if b.le.is_infinite() {
                // Target lands in the +Inf bucket → clamp to the last finite bound.
                return Some(prev_le);
            }
            let span = b.le - prev_le;
            let in_bucket = count - prev_count;
            if in_bucket <= 0.0 {
                return Some(b.le);
            }
            return Some(prev_le + span * (rank - prev_count) / in_bucket);
        }
        prev_le = b.le;
        prev_count = count;
    }
    buckets.last().map(|b| if b.le.is_infinite() { prev_le } else { b.le })
}

/// Read `<name>="<value>"` out of a Prometheus label block (`a="b",c="d"`). Returns the unescaped
/// value (Prometheus escapes `\"`/`\\`/`\n`; our decision labels never contain those, but unescape
/// defensively).
fn label_value(labels: &str, name: &str) -> Option<String> {
    let key = format!("{name}=\"");
    let start = labels.find(&key)? + key.len();
    let tail = &labels[start..];
    // The value ends at the next unescaped quote.
    let mut val = String::new();
    let mut chars = tail.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some('n') => val.push('\n'),
                Some(other) => val.push(other),
                None => break,
            },
            '"' => return Some(val),
            other => val.push(other),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"# HELP waf_requests_total Total requests by final decision.
# TYPE waf_requests_total counter
waf_requests_total{decision="allowed"} 128
waf_requests_total{decision="blocked"} 7
waf_requests_total{decision="rate_limited"} 3
# HELP waf_request_duration_seconds Request handling latency in seconds.
# TYPE waf_request_duration_seconds histogram
waf_request_duration_seconds_bucket{le="0.001"} 100
waf_request_duration_seconds_sum 0.5
waf_request_duration_seconds_count 138
waf_up 1
"#;

    #[test]
    fn extracts_only_requests_total_decisions() {
        let got = parse_requests_total(SAMPLE);
        assert_eq!(
            got,
            vec![
                DecisionCount { decision: "allowed".into(), count: 128 },
                DecisionCount { decision: "blocked".into(), count: 7 },
                DecisionCount { decision: "rate_limited".into(), count: 3 },
            ]
        );
    }

    #[test]
    fn skips_malformed_and_unrelated_lines() {
        let text = "waf_requests_total{decision=\"blocked\"} notanumber\n\
                    waf_requests_total{other=\"x\"} 5\n\
                    waf_requests_total{decision=\"ok\"} 9\n\
                    garbage line\n";
        let got = parse_requests_total(text);
        assert_eq!(got, vec![DecisionCount { decision: "ok".into(), count: 9 }]);
    }

    #[test]
    fn empty_input_yields_nothing() {
        assert!(parse_requests_total("").is_empty());
    }

    const HIST: &str = r#"waf_request_duration_seconds_bucket{le="0.001"} 50
waf_request_duration_seconds_bucket{le="0.005"} 80
waf_request_duration_seconds_bucket{le="0.01"} 95
waf_request_duration_seconds_bucket{le="+Inf"} 100
"#;

    #[test]
    fn parses_latency_buckets_sorted_with_inf() {
        let b = parse_latency_buckets(HIST);
        assert_eq!(b.len(), 4);
        assert_eq!(b[0].le, 0.001);
        assert_eq!(b[0].count, 50);
        assert!(b[3].le.is_infinite());
        assert_eq!(b[3].count, 100);
    }

    #[test]
    fn quantile_interpolates_within_the_bucket() {
        let b = parse_latency_buckets(HIST);
        // p50 → rank 50 lands exactly at the 0.001 boundary (cumulative 50).
        let p50 = histogram_quantile(&b, 0.50).unwrap();
        assert!((p50 - 0.001).abs() < 1e-9, "p50 = {p50}");
        // p90 → rank 90 is inside (0.005, 0.01] where cumulative goes 80→95.
        let p90 = histogram_quantile(&b, 0.90).unwrap();
        assert!(p90 > 0.005 && p90 <= 0.01, "p90 = {p90}");
    }

    #[test]
    fn quantile_none_on_empty_histogram() {
        assert!(histogram_quantile(&[], 0.5).is_none());
        assert!(histogram_quantile(&[LatencyBucket { le: f64::INFINITY, count: 0 }], 0.5).is_none());
    }
}
