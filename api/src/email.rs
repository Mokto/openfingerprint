use std::{collections::HashSet, sync::LazyLock, time::Duration};

use hickory_resolver::{TokioResolver, proto::rr::RData};
use serde::Serialize;

static DISPOSABLE: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    include_str!("../data/disposable_domains.txt")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
});

const FREE_PROVIDERS: &str = "\
    gmail.com yahoo.com yahoo.co.uk yahoo.fr yahoo.de ymail.com rocketmail.com hotmail.com \
    hotmail.co.uk hotmail.fr hotmail.de outlook.com outlook.fr outlook.de live.com \
    live.co.uk msn.com icloud.com me.com mac.com aol.com protonmail.com protonmail.ch \
    proton.me pm.me gmx.com gmx.de gmx.net web.de mail.com email.com yandex.ru yandex.com \
    ya.ru mail.ru inbox.ru list.ru bk.ru zoho.com tutanota.com tuta.io fastmail.com hey.com \
    qq.com 163.com 126.com naver.com libero.it orange.fr free.fr laposte.net sfr.fr \
    t-online.de seznam.cz wp.pl o2.pl interia.pl rediffmail.com";

// Typo targets: only long names, so short corporate domains (aon.com, mi.com) aren't
// "corrected" to aol.com or me.com.
const TYPO_TARGETS: &str = "\
    gmail.com yahoo.com hotmail.com outlook.com icloud.com protonmail.com proton.me \
    yandex.ru yandex.com rocketmail.com";

const ROLE_ACCOUNTS: &str = "\
    abuse admin administrator billing careers contact help hello hostmaster hr info jobs \
    mail marketing noreply no-reply office postmaster root sales security support team \
    webmaster";

fn has(list: &str, item: &str) -> bool {
    list.split_whitespace().any(|x| x == item)
}

#[derive(Serialize, Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Review,
    Block,
}

#[derive(Serialize, Debug, Default)]
pub struct EmailSignals {
    pub normalized: Option<String>,
    pub domain: Option<String>,
    pub disposable: bool,
    pub role: bool,
    pub free_provider: bool,
    /// None when the lookup timed out or failed.
    pub mx: Option<bool>,
    pub did_you_mean: Option<String>,
}

pub struct Normalized {
    pub local: String,
    pub domain: String,
}

impl Normalized {
    pub fn address(&self) -> String {
        format!("{}@{}", self.local, self.domain)
    }
}

pub fn normalize(email: &str) -> Option<Normalized> {
    // ponytail: ASCII dot-atom mailboxes only; use a tested SMTPUTF8/quoted-address parser if needed.
    let email = email.trim().to_ascii_lowercase();
    let (local, domain) = email.rsplit_once('@')?;
    if !email.is_ascii()
        || email.len() > 254
        || local.is_empty()
        || local.len() > 64
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~.".contains(&b))
        || !domain.contains('.')
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label.as_bytes()[0].is_ascii_alphanumeric()
                || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return None;
    }
    let mut local = local.split_once('+').map_or(local, |(l, _)| l).to_string();
    if local.is_empty() || local.ends_with('.') {
        return None;
    }
    let domain = if domain == "googlemail.com" {
        "gmail.com"
    } else {
        domain
    };
    if domain == "gmail.com" {
        local.retain(|c| c != '.');
        if local.is_empty() {
            return None;
        }
    }
    Some(Normalized {
        local,
        domain: domain.to_string(),
    })
}

pub fn is_disposable(domain: &str) -> bool {
    let mut d = domain;
    loop {
        if DISPOSABLE.contains(d) {
            return true;
        }
        match d.split_once('.') {
            Some((_, parent)) if parent.contains('.') => d = parent,
            _ => return false,
        }
    }
}

fn osa_distance(a: &[u8], b: &[u8]) -> usize {
    let mut d = vec![vec![0; b.len() + 1]; a.len() + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    d[0] = (0..=b.len()).collect();
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            d[i][j] = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d[i][j] = d[i][j].min(d[i - 2][j - 2] + 1);
            }
        }
    }
    d[a.len()][b.len()]
}

pub fn suggest_domain(domain: &str) -> Option<&'static str> {
    if has(FREE_PROVIDERS, domain) || domain.len() > 40 {
        return None;
    }
    TYPO_TARGETS
        .split_whitespace()
        .map(|t| (osa_distance(domain.as_bytes(), t.as_bytes()), t))
        .filter(|&(dist, t)| dist == 1 || (dist == 2 && t.len() >= 10))
        .min_by_key(|&(dist, _)| dist)
        .map(|(_, t)| t)
}

pub enum Mx {
    Found,
    Missing,
    Unknown,
}

pub fn resolver(timeout: Duration) -> TokioResolver {
    let mut builder = TokioResolver::builder_tokio().expect("system DNS config");
    let opts = builder.options_mut();
    opts.timeout = timeout;
    opts.attempts = 1;
    opts.cache_size = 10_000;
    opts.positive_min_ttl = Some(Duration::from_secs(3600));
    opts.negative_min_ttl = Some(Duration::from_secs(600));
    builder.build().expect("resolver")
}

pub async fn lookup_mx(resolver: &TokioResolver, domain: &str, timeout: Duration) -> Mx {
    let lookup = tokio::time::timeout(timeout, resolver.mx_lookup(format!("{domain}."))).await;
    match lookup {
        Ok(Ok(found)) => {
            // RFC 7505 null MX: a single "." exchange means the domain accepts no mail.
            let accepts = found.answers().iter().any(|r| match &r.data {
                RData::MX(mx) => !mx.exchange.is_root(),
                _ => false,
            });
            if accepts { Mx::Found } else { Mx::Missing }
        }
        Ok(Err(e)) if e.is_no_records_found() => Mx::Missing,
        _ => Mx::Unknown,
    }
}

pub struct EmailCheck {
    pub reasons: Vec<&'static str>,
    pub signals: EmailSignals,
}

pub fn check_offline(email: &str) -> (EmailCheck, Option<Normalized>) {
    let Some(n) = normalize(email) else {
        let check = EmailCheck {
            reasons: vec!["invalid_email"],
            signals: EmailSignals::default(),
        };
        return (check, None);
    };
    let mut reasons = Vec::new();
    let disposable = is_disposable(&n.domain);
    if disposable {
        reasons.push("disposable_email");
    }
    let role = has(ROLE_ACCOUNTS, &n.local);
    if role {
        reasons.push("role_account");
    }
    let did_you_mean = suggest_domain(&n.domain).map(|d| {
        let original_local = email.trim().rsplit_once('@').map_or("", |(l, _)| l);
        format!("{original_local}@{d}")
    });
    if did_you_mean.is_some() {
        reasons.push("possible_typo");
    }
    let free_provider = has(FREE_PROVIDERS, &n.domain);
    let signals = EmailSignals {
        normalized: Some(n.address()),
        domain: Some(n.domain.clone()),
        disposable,
        role,
        free_provider,
        mx: free_provider.then_some(true),
        did_you_mean,
    };
    (EmailCheck { reasons, signals }, Some(n))
}

pub async fn check(email: &str, resolver: &TokioResolver, timeout: Duration) -> EmailCheck {
    let (mut check, normalized) = check_offline(email);
    if let Some(n) = normalized
        && check.signals.mx.is_none()
        && !check.signals.disposable
    {
        match lookup_mx(resolver, &n.domain, timeout).await {
            Mx::Found => check.signals.mx = Some(true),
            Mx::Missing => {
                check.signals.mx = Some(false);
                check.reasons.push("no_mx");
            }
            Mx::Unknown => check.reasons.push("mx_unknown"),
        }
    }
    check
}

pub fn verdict(reasons: &[&str]) -> Verdict {
    reasons.iter().fold(Verdict::Allow, |v, r| {
        let this = match *r {
            "invalid_email" | "disposable_email" | "no_mx" => Verdict::Block,
            "role_account" | "possible_typo" => Verdict::Review,
            _ => Verdict::Allow,
        };
        v.max(this)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes() {
        let n = |e| normalize(e).map(|n| n.address());
        assert_eq!(
            n(" J.Doe+trial@GoogleMail.com ").as_deref(),
            Some("jdoe@gmail.com")
        );
        assert_eq!(
            n("j.doe+x@example.com").as_deref(),
            Some("j.doe@example.com")
        );
        assert_eq!(n("+x@example.com"), None);
        assert_eq!(n("...+trial@gmail.com"), None);
        assert_eq!(n("not-an-email"), None);
        assert_eq!(n("@github.com"), None);
        assert_eq!(n("a b@github.com"), None);
    }

    #[test]
    fn rejects_malformed_and_unsupported_addresses() {
        for address in [
            "a,b@gmail.com",
            "a:b@gmail.com",
            ".a@gmail.com",
            "a.@gmail.com",
            "a..b@gmail.com",
            "a.+tag@example.com",
            "a@example..com",
            "a@-example.com",
            "a@example-.com",
            "a@exa_mple.com",
            "a@example.com.",
            "\"a\"@example.com",
            "é@example.com",
            "a@exämple.com",
        ] {
            assert!(normalize(address).is_none());
            assert_eq!(check_offline(address).0.reasons, ["invalid_email"]);
        }
        assert!(normalize(&format!("{}@example.com", "a".repeat(65))).is_none());
        assert!(normalize(&format!("a@{}.com", "a".repeat(64))).is_none());
        assert!(normalize(&format!("{}@example.com", "a".repeat(64))).is_some());
        assert!(normalize("o'hara@example.com").is_some());
        assert!(normalize("a@xn--exmple-cua.org").is_some());
    }

    #[test]
    fn offline_signals() {
        let (c, _) = check_offline("octocat@github.com");
        assert!(c.reasons.is_empty() && !c.signals.free_provider && c.signals.mx.is_none());
        assert_eq!(
            check_offline("a@sub.MAILINATOR.com").0.reasons,
            ["disposable_email"]
        );
        assert_eq!(check_offline("Support@acme.io").0.reasons, ["role_account"]);
        let (c, _) = check_offline("Jane@gmail.con");
        assert_eq!(c.reasons, ["possible_typo"]);
        assert_eq!(c.signals.did_you_mean.as_deref(), Some("Jane@gmail.com"));
        assert_eq!(suggest_domain("hotmial.co"), Some("hotmail.com"));
        assert_eq!(suggest_domain("aon.com"), None);
        assert_eq!(suggest_domain("ymail.com"), None);
        assert!(check_offline("x@googlemail.com").0.signals.free_provider);
    }

    #[test]
    fn verdicts() {
        assert_eq!(verdict(&["mx_unknown"]), Verdict::Allow);
        assert_eq!(verdict(&["role_account", "mx_unknown"]), Verdict::Review);
        assert_eq!(verdict(&["possible_typo", "no_mx"]), Verdict::Block);
    }

    #[tokio::test]
    async fn mx_fails_open_on_timeout() {
        use hickory_resolver::{
            config::{NameServerConfig, ResolverConfig},
            net::runtime::TokioRuntimeProvider,
        };
        // TEST-NET-1 never answers.
        let config = ResolverConfig::from_name_servers(vec![NameServerConfig::udp(
            "192.0.2.1".parse().unwrap(),
        )]);
        let resolver = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
            .build()
            .unwrap();
        let start = std::time::Instant::now();
        let c = check("a@example.org", &resolver, Duration::from_millis(200)).await;
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(c.reasons, ["mx_unknown"]);
        assert_eq!(c.signals.mx, None);
    }
}
