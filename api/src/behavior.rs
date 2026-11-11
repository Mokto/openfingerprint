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
    let valid = fields.get("version").and_then(Value::as_u64) == Some(1)
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
            rule_version: 1,
            source: "client_reported",
            patterns: Vec::new(),
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
        rule_version: 1,
        source: "client_reported",
        patterns,
        reason: None,
    }
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
    fn malformed_reports_are_invalid() {
        let mut missing = report(json!({}));
        missing.as_object_mut().unwrap().remove("wheels");
        for value in [
            json!(null),
            json!({}),
            json!({"version": 2}),
            missing,
            report(json!({"version": 2})),
            report(json!({"keys": -1})),
            report(json!({"keys": 1.5})),
            report(json!({"keys": "1"})),
            report(json!({"extra": 0})),
        ] {
            let result = check(value.clone());
            assert_eq!(
                (result.status, result.reason),
                ("invalid_input", Some("invalid_behavior")),
                "{value}"
            );
        }
    }
}
