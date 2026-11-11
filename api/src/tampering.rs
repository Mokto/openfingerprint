use serde::Serialize;
use serde_json::Value;

const PROBES: [(&str, &str); 2] = [
    ("canvasReadbackAltered", "canvas_readback_altered"),
    ("audioRenderAltered", "audio_render_altered"),
];

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
impl Check {
    pub(crate) fn rejected(&self) -> bool {
        self.status == "invalid_input"
    }
}

pub fn check(value: Value) -> Check {
    let mut result = Check {
        status: "invalid_input",
        rule_version: 1,
        source: "client_reported",
        indicators: Vec::new(),
        unavailable_probes: Vec::new(),
        reason: Some("invalid_tampering"),
    };
    let Some(fields) = value.as_object() else {
        return result;
    };
    if fields.get("version").and_then(Value::as_u64) != Some(1)
        || fields.iter().any(|(key, observed)| {
            key != "version"
                && (!PROBES.iter().any(|(name, _)| name == key)
                    || !(observed.is_null() || observed.is_boolean()))
        })
    {
        return result;
    }
    for (name, indicator) in PROBES {
        match fields.get(name).and_then(Value::as_bool) {
            Some(true) => result.indicators.push(indicator),
            None => result.unavailable_probes.push(indicator),
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
    fn unknowns_and_positive_evidence_are_preserved() {
        for (canvas, audio, status, indicators, unavailable) in [
            (json!(false), json!(false), "not_detected", vec![], vec![]),
            (
                json!(true),
                json!(false),
                "detected",
                vec!["canvas_readback_altered"],
                vec![],
            ),
            (
                json!(false),
                json!(true),
                "detected",
                vec!["audio_render_altered"],
                vec![],
            ),
            (
                json!(null),
                json!(false),
                "unknown",
                vec![],
                vec!["canvas_readback_altered"],
            ),
            (
                json!(true),
                json!(null),
                "detected",
                vec!["canvas_readback_altered"],
                vec!["audio_render_altered"],
            ),
        ] {
            let result = check(json!({
                "version": 1, "canvasReadbackAltered": canvas, "audioRenderAltered": audio
            }));
            assert_eq!(result.status, status);
            assert_eq!(result.indicators, indicators);
            assert_eq!(result.unavailable_probes, unavailable);
            assert_eq!(
                (result.rule_version, result.source, result.reason),
                (1, "client_reported", None)
            );
        }
        let missing = check(json!({"version": 1}));
        assert_eq!(missing.status, "unknown");
        assert_eq!(missing.unavailable_probes.len(), 2);
    }

    #[test]
    fn invalid_evidence_gets_no_verdict() {
        for value in [
            json!(null),
            json!(false),
            json!([]),
            json!({}),
            json!({"version": 2}),
            json!({"version": 1, "extra": true}),
            json!({"version": 1, "canvasReadbackAltered": "true"}),
            json!({"version": 1, "audioRenderAltered": 1}),
            json!({"version": 1, "webdriver": true}),
        ] {
            let result = check(value);
            assert_eq!(result.status, "invalid_input");
            assert_eq!(result.reason, Some("invalid_tampering"));
            assert!(result.indicators.is_empty() && result.unavailable_probes.is_empty());
        }
    }
}
