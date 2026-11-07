//! Full email addresses: syntax and role-account detection. The address is only parsed here;
//! it is never stored, logged, echoed or used as a metric label.

use serde::Serialize;

/// Shared mailboxes rather than a person: RFC 2142 names (abuse ... www) plus common business
/// and system mailboxes. Compared after lowercasing, dropping a `+tag` and removing `.`, `-`, `_`.
const ROLES: &[&str] = &[
    "abuse",
    "accounting",
    "accounts",
    "admin",
    "administrator",
    "billing",
    "bounce",
    "bounces",
    "careers",
    "compliance",
    "contact",
    "contactus",
    "customercare",
    "customerservice",
    "customersupport",
    "donotreply",
    "enquiries",
    "enquiry",
    "feedback",
    "finance",
    "ftp",
    "hello",
    "help",
    "helpdesk",
    "hostmaster",
    "hr",
    "info",
    "inquiries",
    "investors",
    "invoices",
    "it",
    "jobs",
    "legal",
    "mailerdaemon",
    "marketing",
    "media",
    "news",
    "noc",
    "noreply",
    "office",
    "orders",
    "partners",
    "postmaster",
    "press",
    "privacy",
    "procurement",
    "purchasing",
    "reception",
    "recruiting",
    "recruitment",
    "root",
    "sales",
    "security",
    "service",
    "support",
    "sysadmin",
    "team",
    "usenet",
    "uucp",
    "webmaster",
    "www",
];

#[derive(Debug, Serialize, PartialEq)]
pub struct EmailCheck {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_account: Option<bool>,
}

/// Splits a dot-atom address into its lowercase local part and domain.
pub fn parse(value: &serde_json::Value) -> Option<(String, String)> {
    let address = value.as_str().filter(|s| s.len() <= 254)?;
    let (local, domain) = address.split_once('@')?;
    let atom = |c: char| c.is_ascii_alphanumeric() || "!#$%&'*+-/=?^_`{|}~".contains(c);
    let valid = (1..=64).contains(&local.len())
        && local
            .split('.')
            .all(|part| !part.is_empty() && part.chars().all(atom))
        && crate::check::domain(domain);
    valid.then(|| (local.to_ascii_lowercase(), domain.to_ascii_lowercase()))
}

pub fn check(local: &str) -> EmailCheck {
    let base = local.split('+').next().unwrap_or(local);
    let compact: String = base
        .chars()
        .filter(|c| !matches!(c, '.' | '-' | '_'))
        .collect();
    EmailCheck {
        status: "checked",
        reason: None,
        role_account: Some(ROLES.binary_search(&compact.as_str()).is_ok()),
    }
}

pub fn invalid() -> EmailCheck {
    EmailCheck {
        status: "invalid_input",
        reason: Some("invalid_email"),
        role_account: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn roles_are_sorted_for_binary_search() {
        assert!(ROLES.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn detects_role_mailboxes_through_tags_case_and_separators() {
        for local in [
            "info",
            "postmaster",
            "no-reply",
            "no_reply",
            "do.not.reply",
            "support+eu",
            "customer.service",
            "mailer-daemon",
        ] {
            assert_eq!(check(local).role_account, Some(true), "{local}");
        }
        for local in [
            "anna",
            "info.anna",
            "salesforce",
            "j.smith",
            "itzel",
            "teamlead",
            "admin2",
        ] {
            assert_eq!(check(local).role_account, Some(false), "{local}");
        }
    }

    #[test]
    fn parses_dot_atom_addresses_only() {
        assert_eq!(
            parse(&json!("Info+X@Example.COM")),
            Some(("info+x".into(), "example.com".into()))
        );
        for bad in [
            json!("example.com"),
            json!("@example.com"),
            json!("a@b@example.com"),
            json!("a..b@example.com"),
            json!(".a@example.com"),
            json!("\"a b\"@example.com"),
            json!("a@localhost"),
            json!("a@-x.com"),
            json!(7),
            json!(format!("{}@example.com", "a".repeat(65))),
        ] {
            assert_eq!(parse(&bad), None, "{bad}");
        }
    }
}
