use std::{
    fmt::Write,
    sync::atomic::{AtomicU64, Ordering},
};

use serde::Serialize;
use serde_json::{Map, Value};

const COUNTS: [&str; 11] = [
    "pointerMoves",
    "mouseClicks",
    "clicksWithoutMovement",
    "centeredClicks",
    "keys",
    "instantKeys",
    "insertedTexts",
    "touches",
    "wheels",
    "untrustedEvents",
    "watchedMs",
];

#[derive(Debug, Serialize)]
#[serde(rename_all(serialize = "camelCase"))]
pub struct Check {
    status: &'static str,
    rule_version: u8,
    source: &'static str,
    patterns: Vec<&'static str>,
    suspicious_click_pattern: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}
impl Check {
    pub(crate) fn rejected(&self) -> bool {
        self.status == "invalid_input"
    }
}

fn counts(value: &Value) -> Option<&Map<String, Value>> {
    let fields = value.as_object()?;
    let valid = matches!(fields.get("version").and_then(Value::as_u64), Some(1 | 2))
        && fields.len() == COUNTS.len() + 1
        && COUNTS
            .iter()
            .all(|name| fields.get(*name).and_then(Value::as_u64).is_some());
    valid.then_some(fields)
}

/// Input patterns since the page called `watch()`. Real users can produce each of them
/// (keyboard-only use, autofill, dictation, on-screen keyboards, collection at page load),
/// so they are reported for the backend to weigh, never as a detection.
pub fn check(value: Value) -> Check {
    let Some(fields) = counts(&value) else {
        return Check {
            status: "invalid_input",
            rule_version: 2,
            source: "client_reported",
            patterns: Vec::new(),
            suspicious_click_pattern: None,
            reason: Some("invalid_behavior"),
        };
    };
    let n = |name: &str| fields[name].as_u64().unwrap_or(0);
    let clicks = n("mouseClicks");
    let mut patterns = Vec::new();
    if clicks > 0 && n("clicksWithoutMovement") == clicks {
        patterns.push("clicks_without_movement");
    }
    if clicks > 0 && n("centeredClicks") == clicks {
        patterns.push("centered_clicks");
    }
    if n("keys") > 0 && n("instantKeys") * 2 >= n("keys") {
        patterns.push("instant_keys");
    }
    if n("insertedTexts") > 0 {
        patterns.push("text_without_keys");
    }
    if [
        "pointerMoves",
        "mouseClicks",
        "keys",
        "insertedTexts",
        "touches",
        "wheels",
    ]
    .iter()
    .all(|name| n(name) == 0)
    {
        patterns.push("no_input");
    }
    Check {
        status: "observed",
        rule_version: 2,
        source: "client_reported",
        suspicious_click_pattern: (fields["version"] == 2 && clicks >= 3).then(|| {
            patterns.contains(&"clicks_without_movement") && patterns.contains(&"centered_clicks")
        }),
        patterns,
        reason: None,
    }
}

const SAMPLES: [&str; 6] = ["0", "1", "2", "3_4", "5_9", "10_plus"];
const PATTERNS: [&str; 5] = [
    "clicks_without_movement",
    "centered_clicks",
    "instant_keys",
    "text_without_keys",
    "no_input",
];
static MISSING: AtomicU64 = AtomicU64::new(0);
static CLICK_FLAGS: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
static OBSERVATIONS: [[AtomicU64; SAMPLES.len()]; 2] =
    [const { [const { AtomicU64::new(0) }; SAMPLES.len()] }; 2];
static MATCHES: [[[AtomicU64; PATTERNS.len()]; SAMPLES.len()]; 2] =
    [const { [const { [const { AtomicU64::new(0) }; PATTERNS.len()] }; SAMPLES.len()] }; 2];

pub(crate) fn observe_stored(value: &Value) {
    if value.is_null() {
        MISSING.fetch_add(1, Ordering::Relaxed);
        CLICK_FLAGS[2].fetch_add(1, Ordering::Relaxed);
        return;
    }
    let Some(fields) = counts(value) else {
        return;
    };
    let version = fields["version"].as_u64().unwrap() as usize - 1;
    let sample = match fields["mouseClicks"].as_u64().unwrap() {
        0 => 0,
        1 => 1,
        2 => 2,
        3..=4 => 3,
        5..=9 => 4,
        _ => 5,
    };
    OBSERVATIONS[version][sample].fetch_add(1, Ordering::Relaxed);
    let result = check(value.clone());
    let flag = match result.suspicious_click_pattern {
        Some(true) => 0,
        Some(false) => 1,
        None => 2,
    };
    CLICK_FLAGS[flag].fetch_add(1, Ordering::Relaxed);
    for pattern in result.patterns {
        if let Some(i) = PATTERNS.iter().position(|p| *p == pattern) {
            MATCHES[version][sample][i].fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub(crate) fn metrics() -> String {
    let mut out = String::from(
        "# HELP openfingerprint_behavior_observations_total Stored identification snapshots by evidence version and mouse-click sample size; not unique visitors.\n# TYPE openfingerprint_behavior_observations_total counter\n",
    );
    let _ = writeln!(
        out,
        "openfingerprint_behavior_observations_total{{evidence=\"missing\",mouse_clicks=\"unknown\"}} {}",
        MISSING.load(Ordering::Relaxed)
    );
    for (version, samples) in OBSERVATIONS.iter().enumerate() {
        for (sample, count) in SAMPLES.iter().zip(samples) {
            let _ = writeln!(
                out,
                "openfingerprint_behavior_observations_total{{evidence=\"v{}\",mouse_clicks=\"{sample}\"}} {}",
                version + 1,
                count.load(Ordering::Relaxed)
            );
        }
    }
    out.push_str("# HELP openfingerprint_behavior_patterns_total Descriptive pattern matches per stored identification snapshot; frequency is not accuracy.\n# TYPE openfingerprint_behavior_patterns_total counter\n");
    for (version, samples) in MATCHES.iter().enumerate() {
        for (sample, patterns) in SAMPLES.iter().zip(samples) {
            for (pattern, count) in PATTERNS.iter().zip(patterns) {
                let _ = writeln!(
                    out,
                    "openfingerprint_behavior_patterns_total{{evidence=\"v{}\",mouse_clicks=\"{sample}\",pattern=\"{pattern}\"}} {}",
                    version + 1,
                    count.load(Ordering::Relaxed)
                );
            }
        }
    }
    out.push_str("# HELP openfingerprint_suspicious_click_patterns_total Click-pattern context flags per stored identification snapshot, not automation verdicts or accuracy.\n# TYPE openfingerprint_suspicious_click_patterns_total counter\n");
    for (result, count) in ["true", "false", "unknown"].iter().zip(&CLICK_FLAGS) {
        let _ = writeln!(
            out,
            "openfingerprint_suspicious_click_patterns_total{{result=\"{result}\"}} {}",
            count.load(Ordering::Relaxed)
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn report(extra: Value) -> Value {
        let mut value = json!({"version": 1});
        for name in COUNTS {
            value[name] = json!(0);
        }
        for (name, count) in extra.as_object().unwrap() {
            value[name] = count.clone();
        }
        value
    }

    #[test]
    fn patterns_follow_the_counts() {
        for (extra, patterns) in [
            (json!({}), vec!["no_input"]),
            (
                json!({"pointerMoves": 2, "mouseClicks": 2, "clicksWithoutMovement": 2, "centeredClicks": 2}),
                vec!["clicks_without_movement", "centered_clicks"],
            ),
            (
                json!({"pointerMoves": 40, "mouseClicks": 2, "clicksWithoutMovement": 1, "centeredClicks": 1}),
                vec![],
            ),
            (json!({"keys": 4, "instantKeys": 2}), vec!["instant_keys"]),
            (json!({"keys": 5, "instantKeys": 2}), vec![]),
            (json!({"insertedTexts": 1}), vec!["text_without_keys"]),
            (
                json!({"untrustedEvents": 3, "watchedMs": 900}),
                vec!["no_input"],
            ),
        ] {
            let result = check(report(extra.clone()));
            assert_eq!(result.status, "observed", "{extra}");
            assert_eq!(result.patterns, patterns, "{extra}");
        }
    }

    #[test]
    fn both_evidence_versions_keep_descriptive_rule_semantics() {
        for version in [1, 2] {
            for clicks in [1, 2, 4, 5, 10, 100] {
                let result = check(report(json!({
                    "version": version, "mouseClicks": clicks,
                    "clicksWithoutMovement": clicks, "centeredClicks": clicks
                })));
                assert_eq!(result.rule_version, 2);
                assert_eq!(
                    result.patterns,
                    ["clicks_without_movement", "centered_clicks"]
                );
                assert_eq!(result.status, "observed");
                let mixed = check(report(json!({
                    "version": version, "mouseClicks": clicks + 1,
                    "clicksWithoutMovement": clicks, "centeredClicks": clicks
                })));
                assert!(mixed.patterns.is_empty());
            }
            for input in ["keys", "touches", "wheels", "pointerMoves"] {
                let mut value = report(json!({"version": version}));
                value[input] = json!(1);
                assert!(check(value).patterns.is_empty(), "{input}");
            }
        }
    }

    #[test]
    fn suspicious_clicks_need_v2_samples_and_both_patterns() {
        for version in [1, 2] {
            for clicks in 0_u64..=10 {
                for (low, centered) in [
                    (clicks, clicks),
                    (clicks.saturating_sub(1), clicks),
                    (clicks, clicks.saturating_sub(1)),
                ] {
                    let result = check(report(json!({
                        "version": version, "mouseClicks": clicks,
                        "clicksWithoutMovement": low, "centeredClicks": centered
                    })));
                    let expected = (version == 2 && clicks >= 3)
                        .then_some(low == clicks && centered == clicks);
                    assert_eq!(
                        result.suspicious_click_pattern, expected,
                        "{version}/{clicks}/{low}/{centered}"
                    );
                    assert_eq!(
                        serde_json::to_value(result).unwrap()["suspiciousClickPattern"],
                        json!(expected)
                    );
                }
            }
        }
        for input in [
            "keys",
            "touches",
            "wheels",
            "insertedTexts",
            "untrustedEvents",
        ] {
            let mut value = report(json!({"version": 2}));
            value[input] = json!(10);
            assert_eq!(check(value).suspicious_click_pattern, None, "{input}");
        }
    }

    #[test]
    fn malformed_reports_are_invalid() {
        let mut missing = report(json!({}));
        missing.as_object_mut().unwrap().remove("wheels");
        for value in [
            json!(null),
            json!({}),
            json!({"version": 3}),
            missing,
            report(json!({"version": 3})),
            report(json!({"keys": -1})),
            report(json!({"keys": 1.5})),
            report(json!({"keys": "1"})),
            report(json!({"extra": 0})),
        ] {
            let result = check(value.clone());
            assert_eq!(result.suspicious_click_pattern, None);
            assert_eq!(
                (result.status, result.reason),
                ("invalid_input", Some("invalid_behavior")),
                "{value}"
            );
        }
    }
}
