use std::{
    fmt::Write,
    sync::atomic::{AtomicU64, Ordering},
};

use serde::Serialize;
use serde_json::Value;

/// The SDK's automation evidence version: the only one accepted.
const VERSION: u64 = 7;
/// Observed only on pages that call the SDK's `watch()`, and only in Chromium and Firefox, so
/// null here does not make the verdict unknown.
const OPTIONAL: &str = "protocolScript";
const PROBES: [(&str, &str); 20] = [
    ("webdriver", "webdriver"),
    ("headlessUserAgent", "headless_user_agent"),
    ("seleniumArtifacts", "selenium_artifacts"),
    ("phantomArtifacts", "phantom_artifacts"),
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
    ("driverArtifacts", "driver_artifacts"),
    ("engineMismatch", "engine_mismatch"),
    ("userAgentDataMismatch", "user_agent_data_mismatch"),
    ("proportionalMonospace", "proportional_monospace"),
    ("engineApiMismatch", "engine_api_mismatch"),
    ("protocolScript", "protocol_script"),
];

const STATUSES: [&str; 3] = ["detected", "unknown", "not_detected"];
static STATUS_COUNTS: [AtomicU64; STATUSES.len()] = [const { AtomicU64::new(0) }; STATUSES.len()];
static INDICATOR_COUNTS: [AtomicU64; PROBES.len()] = [const { AtomicU64::new(0) }; PROBES.len()];

/// Counts of evaluated identifications, by verdict and by indicator. Nothing identifies a visitor:
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
    for ((_, indicator), count) in PROBES.iter().zip(&INDICATOR_COUNTS) {
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
        if let Some(i) = PROBES.iter().position(|(_, name)| name == indicator) {
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
impl Check {
    pub(crate) fn rejected(&self) -> bool {
        self.status == "invalid_input"
    }
}

pub fn check(value: Value) -> Check {
    let mut result = Check {
        status: "invalid_input",
        rule_version: VERSION as u8,
        source: "client_reported",
        indicators: Vec::new(),
        unavailable_probes: Vec::new(),
        reason: Some("invalid_automation"),
    };
    if value.get("version").and_then(Value::as_u64) != Some(VERSION) {
        return result;
    }
    let Some(fields) = value.as_object() else {
        return result;
    };
    if fields.iter().any(|(key, observed)| {
        key != "version"
            && (!PROBES.iter().any(|(name, _)| *name == key)
                || !(observed.is_null() || observed.is_boolean()))
    }) {
        return result;
    }
    let mut unknown = false;
    for (name, indicator) in PROBES {
        match fields.get(name).and_then(Value::as_bool) {
            Some(true) => result.indicators.push(indicator),
            None => {
                result.unavailable_probes.push(indicator);
                unknown |= name != OPTIONAL;
            }
            Some(false) => {}
        }
    }
    result.status = if !result.indicators.is_empty() {
        "detected"
    } else if unknown {
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

    fn report(extra: Value) -> Value {
        let mut report = json!({"version": VERSION});
        for (name, _) in PROBES {
            report[name] = json!(false);
        }
        for (name, observed) in extra.as_object().unwrap() {
            report[name] = observed.clone();
        }
        report
    }

    #[test]
    fn each_probe_is_reported_on_its_own_and_unknowns_stay_unknown() {
        let clean = check(report(json!({})));
        assert_eq!((clean.status, clean.rule_version), ("not_detected", 7));
        assert_eq!(clean.source, "client_reported");
        for (field, indicator) in PROBES {
            let result = check(report(json!({ (field): true })));
            assert_eq!(
                (result.status, result.indicators),
                ("detected", vec![indicator])
            );
            let unknown = check(report(json!({ (field): null })));
            assert_eq!(
                (unknown.status, unknown.unavailable_probes),
                (
                    if field == OPTIONAL {
                        "not_detected"
                    } else {
                        "unknown"
                    },
                    vec![indicator]
                ),
                "protocol_script is null without watch() and never makes the verdict unknown"
            );
        }
        let mixed = check(report(json!({"webdriver": true, "driverArtifacts": null})));
        assert_eq!(
            (mixed.status, mixed.indicators, mixed.unavailable_probes),
            ("detected", vec!["webdriver"], vec!["driver_artifacts"]),
            "a positive probe wins over unknowns"
        );
        assert_eq!(
            check(json!({"version": VERSION})).unavailable_probes.len(),
            PROBES.len()
        );
    }

    #[test]
    fn other_versions_and_malformed_evidence_have_no_verdict() {
        for value in [
            json!(null),
            json!([]),
            json!({}),
            json!({"version": 1, "webdriver": false}),
            json!({"version": 6}),
            json!({"version": 8}),
            json!({"version": "7"}),
            json!({"version": 7, "extra": true}),
            json!({"version": 7, "webdriver": "false"}),
            json!({"version": 7, "protocolScript": 1}),
        ] {
            let result = check(value);
            assert_eq!(
                (result.status, result.reason),
                ("invalid_input", Some("invalid_automation"))
            );
            assert!(result.indicators.is_empty() && result.unavailable_probes.is_empty());
        }
    }

    #[test]
    fn metrics_count_verdicts_and_each_positive_probe() {
        let value = |text: &str, series: &str| -> u64 {
            text.lines()
                .find_map(|l| l.strip_prefix(series))
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or_else(|| panic!("missing {series}"))
        };
        let (detected, cdp) = (
            "openfingerprint_automation_checks_total{status=\"detected\"} ",
            "openfingerprint_automation_indicators_total{indicator=\"cdp_detected\"} ",
        );
        let before = metrics();
        check(report(json!({"cdpDetected": true})));
        check(report(json!({"cdpDetected": true, "webdriver": true})));
        let after = metrics();
        // Other tests share these statics, so assert increases only.
        assert!(value(&after, detected) >= value(&before, detected) + 2);
        assert!(value(&after, cdp) >= value(&before, cdp) + 2);
    }
}
