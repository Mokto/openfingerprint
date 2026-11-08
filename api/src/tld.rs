//! Whether a domain sits on a TLD that registrars sell at teaser prices (`cheapTld`). It says what
//! the registration cost an attacker, nothing about the site; real businesses use these TLDs too.

use serde::{Deserialize, Serialize};
use std::{collections::HashSet, sync::OnceLock};

#[derive(Deserialize)]
struct Prices {
    cheap: HashSet<String>,
    other: HashSet<String>,
}

fn prices() -> &'static Prices {
    static PRICES: OnceLock<Prices> = OnceLock::new();
    PRICES.get_or_init(|| {
        serde_json::from_str(include_str!("../data/tld-prices.json"))
            .expect("bundled TLD prices are valid")
    })
}

#[derive(Serialize)]
pub struct CheapTld {
    value: Option<bool>,
    status: &'static str,
    scope: &'static str,
}

impl CheapTld {
    /// `domain` is lowercase without a trailing dot. A TLD the price list does not cover is unknown.
    pub fn of(domain: &str) -> Self {
        let tld = domain.rsplit('.').next().unwrap_or_default();
        let prices = prices();
        let (value, status) = if prices.cheap.contains(tld) {
            (Some(true), "cheap")
        } else if prices.other.contains(tld) {
            (Some(false), "not_cheap")
        } else {
            (None, "unknown_tld")
        };
        Self {
            value,
            status,
            scope: "tld_registration_price",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(domain: &str) -> &'static str {
        CheapTld::of(domain).status
    }

    #[test]
    fn teaser_priced_generic_tlds_are_cheap_and_country_codes_are_not() {
        assert_eq!(status("example.xyz"), "cheap");
        assert_eq!(status("a.b.top"), "cheap");
        assert_eq!(status("example.com"), "not_cheap");
        assert_eq!(status("example.de"), "not_cheap");
        assert_eq!(status("example.co.uk"), "not_cheap");
        assert_eq!(status("example.invalid"), "unknown_tld");
        assert_eq!(CheapTld::of("example.invalid").value, None);
    }

    #[test]
    fn bundled_lists_are_disjoint_generic_and_cover_the_common_tlds() {
        let prices = prices();
        assert!(prices.cheap.is_disjoint(&prices.other));
        assert!(
            prices
                .cheap
                .iter()
                .all(|t| t.len() > 2 && !t.starts_with("xn--"))
        );
        for tld in ["com", "net", "org", "io", "de", "uk"] {
            assert!(prices.other.contains(tld), "{tld}");
        }
        assert!(prices.cheap.len() > 20 && prices.other.len() > 300);
    }
}
