use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Evidence {
    version: u8,
    webdriver: Option<bool>,
    headless_user_agent: Option<bool>,
    selenium_artifacts: Option<bool>,
    phantom_artifacts: Option<bool>,
    software_renderer: Option<bool>,
    missing_chrome_object: Option<bool>,
    no_languages: Option<bool>,
    platform_inconsistent: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct Check {
    status: &'static str,
    rule_version: u8,
    source: &'static str,
    indicators: Vec<&'static str>,
    unavailable_probes: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}

pub fn check(value: serde_json::Value) -> Check {
    let mut result = Check {
        status: "invalid_input",
        rule_version: 1,
        source: "client_reported",
        indicators: Vec::new(),
        unavailable_probes: Vec::new(),
        reason: Some("invalid_automation"),
    };
    let Ok(evidence) = serde_json::from_value::<Evidence>(value) else {
        return result;
    };
    let added = [
        ("software_renderer", evidence.software_renderer),
        ("missing_chrome_object", evidence.missing_chrome_object),
        ("no_languages", evidence.no_languages),
        ("platform_inconsistent", evidence.platform_inconsistent),
    ];
    // Version 1 predates the added probes, so a v1 report must not carry them.
    if !matches!(evidence.version, 1 | 2)
        || (evidence.version == 1 && added.iter().any(|(_, v)| v.is_some()))
    {
        return result;
    }
    let mut probes = vec![
        ("webdriver", evidence.webdriver),
        ("headless_user_agent", evidence.headless_user_agent),
        ("selenium_artifacts", evidence.selenium_artifacts),
        ("phantom_artifacts", evidence.phantom_artifacts),
    ];
    if evidence.version == 2 {
        probes.extend(added);
    }
    result.rule_version = evidence.version;
    for (name, observed) in probes {
        match observed {
            Some(true) => result.indicators.push(name),
            None => result.unavailable_probes.push(name),
            Some(false) => {}
        }
    }
    result.status = if !result.indicators.is_empty() {
        "detected"
    } else if !result.unavailable_probes.is_empty() {
        "unknown"
    } else {
        "not_detected"
    };
    result.reason = None;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
        let result = check(json!({"version": 2}));
        assert_eq!(result.rule_version, 2);
        assert_eq!(result.unavailable_probes.len(), 8);
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
            json!({"version": 1, "softwareRenderer": false}),
            json!({"version": 2, "noLanguages": "true"}),
            json!({"version": -1}),
            json!({"version": 1.5}),
            json!({"version": "1"}),
            json!({"version": 1, "extra": true}),
            json!({"version": 1, "webdriver": "false"}),
            json!({"version": 1, "headlessUserAgent": 0}),
            json!({"version": 1, "seleniumArtifacts": []}),
            json!({"version": 1, "phantomArtifacts": {}}),
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
        for (field, reason) in [
            ("softwareRenderer", "software_renderer"),
            ("missingChromeObject", "missing_chrome_object"),
            ("noLanguages", "no_languages"),
            ("platformInconsistent", "platform_inconsistent"),
        ] {
            let result = check(json!({"version": 2, (field): true}));
            assert_eq!(result.rule_version, 2);
            assert_eq!(result.indicators, [reason]);
            assert_eq!(result.unavailable_probes.len(), 7);
        }
    }
}
