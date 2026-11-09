use std::{
    fmt::Write,
    sync::atomic::{AtomicU64, Ordering},
};

use serde::Serialize;
use serde_json::Value;

const V1: [(&str, &str); 4] = [
    ("webdriver", "webdriver"),
    ("headlessUserAgent", "headless_user_agent"),
    ("seleniumArtifacts", "selenium_artifacts"),
    ("phantomArtifacts", "phantom_artifacts"),
];
const V2: [(&str, &str); 10] = [
    ("platformMismatch", "platform_mismatch"),
    ("missingChromeObject", "missing_chrome_object"),
    (
        "notificationPermissionQuirk",
        "notification_permission_quirk",
    ),
    ("emptyPlugins", "empty_plugins"),
    ("emptyLanguages", "empty_languages"),
    ("softwareRenderer", "software_renderer"),
    ("zeroDimensions", "zero_dimensions"),
    ("cdpDetected", "cdp_detected"),
    ("nativeFunctionTampering", "native_function_tampering"),
    ("workerUserAgentMismatch", "worker_user_agent_mismatch"),
];

const STATUSES: [&str; 3] = ["detected", "unknown", "not_detected"];
static STATUS_COUNTS: [AtomicU64; STATUSES.len()] = [const { AtomicU64::new(0) }; STATUSES.len()];
static INDICATOR_COUNTS: [AtomicU64; V1.len() + V2.len()] =
    [const { AtomicU64::new(0) }; V1.len() + V2.len()];

/// Counts of evaluated tokens, by verdict and by indicator. Nothing identifies a visitor:
/// they show which probes fire in practice, since one indicator is enough for `detected`.
pub fn metrics() -> String {
    let mut out = String::from(
        "# HELP openfingerprint_automation_checks_total Valid automation reports evaluated, by verdict.\n# TYPE openfingerprint_automation_checks_total counter\n",
    );
    for (status, count) in STATUSES.iter().zip(&STATUS_COUNTS) {
        let _ = writeln!(
            out,
            "openfingerprint_automation_checks_total{{status=\"{status}\"}} {}",
            count.load(Ordering::Relaxed)
        );
    }
    out.push_str(
        "# HELP openfingerprint_automation_indicators_total Valid automation reports in which each probe was positive.\n# TYPE openfingerprint_automation_indicators_total counter\n",
    );
    for ((_, indicator), count) in V1.iter().chain(&V2).zip(&INDICATOR_COUNTS) {
        let _ = writeln!(
            out,
            "openfingerprint_automation_indicators_total{{indicator=\"{indicator}\"}} {}",
            count.load(Ordering::Relaxed)
        );
    }
    out
}

fn record(result: &Check) {
    if let Some(i) = STATUSES.iter().position(|s| *s == result.status) {
        STATUS_COUNTS[i].fetch_add(1, Ordering::Relaxed);
    }
    for indicator in &result.indicators {
        if let Some(i) = V1.iter().chain(&V2).position(|(_, name)| name == indicator) {
            INDICATOR_COUNTS[i].fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all(serialize = "camelCase"))]
pub struct Check {
    status: &'static str,
    rule_version: u8,
    source: &'static str,
    indicators: Vec<&'static str>,
    unavailable_probes: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}

pub fn check(value: Value) -> Check {
    let mut result = Check {
        status: "invalid_input",
        rule_version: 1,
        source: "client_reported",
        indicators: Vec::new(),
        unavailable_probes: Vec::new(),
        reason: Some("invalid_automation"),
    };
    let version = match value.get("version").and_then(Value::as_u64) {
        Some(1) => 1,
        Some(2) => 2,
        _ => return result,
    };
    let probes: Vec<_> = V1
        .iter()
        .chain(if version == 2 { V2.iter() } else { [].iter() })
        .collect();
    let Some(fields) = value.as_object() else {
        return result;
    };
    if fields.iter().any(|(key, observed)| {
        key != "version"
            && (!probes.iter().any(|(name, _)| name == key)
                || !(observed.is_null() || observed.is_boolean()))
    }) {
        return result;
    }
    for (name, indicator) in probes {
        match fields.get(*name).and_then(Value::as_bool) {
            Some(true) => result.indicators.push(indicator),
            None => result.unavailable_probes.push(indicator),
            Some(false) => {}
        }
    }
    result.rule_version = version;
    result.status = if !result.indicators.is_empty() {
        "detected"
    } else if !result.unavailable_probes.is_empty() {
        "unknown"
    } else {
        "not_detected"
    };
    result.reason = None;
    record(&result);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn metrics_count_verdicts_and_each_positive_probe() {
        let value = |text: &str, series: &str| -> u64 {
            text.lines()
                .find_map(|l| l.strip_prefix(series))
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or_else(|| panic!("missing {series}"))
        };
        let (detected, platform, cdp, clean) = (
            "openfingerprint_automation_checks_total{status=\"detected\"} ",
            "openfingerprint_automation_indicators_total{indicator=\"platform_mismatch\"} ",
            "openfingerprint_automation_indicators_total{indicator=\"cdp_detected\"} ",
            "openfingerprint_automation_checks_total{status=\"not_detected\"} ",
        );
        let before = metrics();
        let all_false = |extra: Value| {
            let mut report = json!({"version": 2});
            for (name, _) in V1.iter().chain(&V2) {
                report[*name] = json!(false);
            }
            for (name, observed) in extra.as_object().unwrap() {
                report[name] = observed.clone();
            }
            report
        };
        check(all_false(
            json!({"platformMismatch": true, "cdpDetected": true}),
        ));
        check(all_false(json!({"cdpDetected": true})));
        check(all_false(json!({})));
        check(json!({"version": 3}));
        let after = metrics();
        // Other tests share these statics, so assert increases only.
        assert!(value(&after, detected) >= value(&before, detected) + 2);
        assert!(value(&after, platform) > value(&before, platform));
        assert!(value(&after, cdp) >= value(&before, cdp) + 2);
        assert!(value(&after, clean) > value(&before, clean));
    }

    #[test]
    fn all_observation_combinations_preserve_unknowns_and_positive_evidence() {
        for mask in 0..81 {
            let mut n = mask;
            let values: Vec<Option<bool>> = (0..4)
                .map(|_| {
                    let value = [None, Some(false), Some(true)][n % 3];
                    n /= 3;
                    value
                })
                .collect();
            let result = check(json!({
                "version": 1,
                "webdriver": values[0],
                "headlessUserAgent": values[1],
                "seleniumArtifacts": values[2],
                "phantomArtifacts": values[3]
            }));
            assert_eq!(result.rule_version, 1);
            assert_eq!(result.source, "client_reported");
            assert_eq!(result.reason, None);
            assert_eq!(
                result.indicators.len(),
                values.iter().filter(|v| **v == Some(true)).count()
            );
            assert_eq!(
                result.unavailable_probes.len(),
                values.iter().filter(|v| v.is_none()).count()
            );
            assert_eq!(
                result.status,
                if values.contains(&Some(true)) {
                    "detected"
                } else if values.contains(&None) {
                    "unknown"
                } else {
                    "not_detected"
                }
            );
        }
        let result = check(json!({"version": 1}));
        assert_eq!(result.status, "unknown");
        assert_eq!(result.unavailable_probes.len(), 4);
        for name in [
            "webdriver",
            "headless_user_agent",
            "selenium_artifacts",
            "phantom_artifacts",
        ] {
            assert!(result.unavailable_probes.contains(&name));
        }
    }

    #[test]
    fn invalid_evidence_does_not_produce_a_verdict() {
        for value in [
            json!(null),
            json!(false),
            json!([]),
            json!("automation"),
            json!({}),
            json!({"version": 3}),
            json!({"version": -1}),
            json!({"version": 1.5}),
            json!({"version": "1"}),
            json!({"version": 1, "extra": true}),
            json!({"version": 1, "webdriver": "false"}),
            json!({"version": 1, "headlessUserAgent": 0}),
            json!({"version": 1, "seleniumArtifacts": []}),
            json!({"version": 1, "phantomArtifacts": {}}),
            json!({"version": 1, "cdpDetected": true}),
            json!({"version": 2, "extra": true}),
            json!({"version": 2, "cdpDetected": "true"}),
            json!({"version": 2, "softwareRenderer": 1}),
        ] {
            let result = check(value);
            assert_eq!(result.status, "invalid_input");
            assert_eq!(result.reason, Some("invalid_automation"));
            assert!(result.indicators.is_empty());
            assert!(result.unavailable_probes.is_empty());
        }
    }

    #[test]
    fn reason_codes_match_each_observation() {
        for (field, reason) in [
            ("webdriver", "webdriver"),
            ("headlessUserAgent", "headless_user_agent"),
            ("seleniumArtifacts", "selenium_artifacts"),
            ("phantomArtifacts", "phantom_artifacts"),
        ] {
            let result = check(json!({"version": 1, (field): true}));
            assert_eq!(result.indicators, [reason]);
            assert_eq!(result.unavailable_probes.len(), 3);
        }
    }

    #[test]
    fn version_two_reports_new_probes_in_order() {
        let result = check(json!({"version": 2}));
        assert_eq!(result.rule_version, 2);
        assert_eq!(result.status, "unknown");
        assert_eq!(result.unavailable_probes.len(), 14);
        for (field, reason) in V2 {
            let result = check(json!({"version": 2, (field): true}));
            assert_eq!(result.status, "detected");
            assert_eq!(result.indicators, [reason]);
            assert_eq!(result.unavailable_probes.len(), 13);
        }
        let all_false: serde_json::Map<String, serde_json::Value> = [("version", json!(2))]
            .into_iter()
            .chain(V1.iter().chain(&V2).map(|(name, _)| (*name, json!(false))))
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        let result = check(serde_json::Value::Object(all_false));
        assert_eq!(result.status, "not_detected");
        assert!(result.indicators.is_empty() && result.unavailable_probes.is_empty());
    }
}
