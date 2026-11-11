//! Latency histograms. Labels are fixed enums, never request data, so they cannot carry
//! domains or addresses and their cardinality is bounded.
use std::{
    fmt::Write,
    future::Future,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

const BOUNDS: [f64; 12] = [
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0,
];

struct Histogram {
    buckets: [AtomicU64; BOUNDS.len() + 1],
    sum_micros: AtomicU64,
}
impl Histogram {
    const fn new() -> Self {
        Self {
            buckets: [const { AtomicU64::new(0) }; BOUNDS.len() + 1],
            sum_micros: AtomicU64::new(0),
        }
    }
    fn observe(&self, elapsed: Duration) {
        let seconds = elapsed.as_secs_f64();
        let i = BOUNDS
            .iter()
            .position(|b| seconds <= *b)
            .unwrap_or(BOUNDS.len());
        self.buckets[i].fetch_add(1, Ordering::Relaxed);
        self.sum_micros
            .fetch_add(elapsed.as_micros() as u64, Ordering::Relaxed);
    }
    fn render(&self, out: &mut String, name: &str, labels: &str) {
        let mut cumulative = 0;
        for (bound, bucket) in BOUNDS.iter().zip(&self.buckets) {
            cumulative += bucket.load(Ordering::Relaxed);
            let _ = writeln!(out, "{name}_bucket{{{labels},le=\"{bound}\"}} {cumulative}");
        }
        cumulative += self.buckets[BOUNDS.len()].load(Ordering::Relaxed);
        let sum = self.sum_micros.load(Ordering::Relaxed) as f64 / 1e6;
        let _ = writeln!(out, "{name}_bucket{{{labels},le=\"+Inf\"}} {cumulative}");
        let _ = writeln!(out, "{name}_sum{{{labels}}} {sum}");
        let _ = writeln!(out, "{name}_count{{{labels}}} {cumulative}");
    }
}

/// A unit of work inside `/v1/check`. The `domain_*` steps run concurrently, so the
/// `domain` step lasts as long as the slowest of them, not their sum. `dns_lookup`,
/// `redis_*`, `replay`, `rdap_fetch` and `whois_fetch` are the network calls beneath them; a cached
/// registration performs no `rdap_fetch`/`whois_fetch`.
#[derive(Clone, Copy)]
pub enum Step {
    Evidence,
    Domain,
    DomainMx,
    DomainRegistration,
    DomainMailAuth,
    IpCountry,
    IpNetwork,
    DnsLookup,
    RedisGet,
    RedisSet,
    Replay,
    Identification,
    RdapFetch,
    WhoisFetch,
}
const STEPS: [&str; 14] = [
    "evidence",
    "domain",
    "domain_mx",
    "domain_registration",
    "domain_mail_auth",
    "ip_country",
    "ip_network",
    "dns_lookup",
    "redis_get",
    "redis_set",
    "replay",
    "identification",
    "rdap_fetch",
    "whois_fetch",
];
static STEP_TIMES: [Histogram; STEPS.len()] = [const { Histogram::new() }; STEPS.len()];

pub const ROUTES: [&str; 4] = ["check", "identify", "rpc", "other"];
const CLASSES: [&str; 4] = ["2xx", "4xx", "5xx", "other"];
static REQUEST_TIMES: [[Histogram; CLASSES.len()]; ROUTES.len()] =
    [const { [const { Histogram::new() }; CLASSES.len()] }; ROUTES.len()];

pub fn route(path: &str) -> usize {
    match path {
        "/v1/check" => 0,
        "/v1/identify" => 1,
        _ if crate::rpc::is_rpc(path) => 2,
        _ => 3,
    }
}
pub fn observe_request(route: usize, status: u16, elapsed: Duration) {
    let class = match status / 100 {
        2 => 0,
        4 => 1,
        5 => 2,
        _ => 3,
    };
    REQUEST_TIMES[route][class].observe(elapsed);
}

/// Records on drop, so a step cut short by a timeout or a disconnecting caller still counts.
pub struct Timer(Step, Instant);
pub fn start(step: Step) -> Timer {
    Timer(step, Instant::now())
}
impl Drop for Timer {
    fn drop(&mut self) {
        STEP_TIMES[self.0 as usize].observe(self.1.elapsed());
    }
}
pub async fn timed<F: Future>(step: Step, future: F) -> F::Output {
    let _timer = start(step);
    future.await
}

pub fn render() -> String {
    let mut out = String::from(
        "# HELP openfingerprint_http_request_duration_seconds Time to produce a response, by route and status class.\n# TYPE openfingerprint_http_request_duration_seconds histogram\n",
    );
    for (route, row) in ROUTES.iter().zip(&REQUEST_TIMES) {
        for (class, histogram) in CLASSES.iter().zip(row) {
            histogram.render(
                &mut out,
                "openfingerprint_http_request_duration_seconds",
                &format!("route=\"{route}\",status=\"{class}\""),
            );
        }
    }
    out.push_str(
        "# HELP openfingerprint_check_step_duration_seconds Time spent in each step of /v1/check and its network calls. domain_* steps run concurrently.\n# TYPE openfingerprint_check_step_duration_seconds histogram\n",
    );
    for (step, histogram) in STEPS.iter().zip(&STEP_TIMES) {
        histogram.render(
            &mut out,
            "openfingerprint_check_step_duration_seconds",
            &format!("step=\"{step}\""),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn count(text: &str, series: &str) -> u64 {
        text.lines()
            .find_map(|l| l.strip_prefix(series))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or_else(|| panic!("missing {series}"))
    }

    #[tokio::test]
    async fn steps_and_requests_land_in_cumulative_buckets_even_when_cancelled() {
        // Other tests share these statics, so assert increases and monotonicity only.
        let total = "openfingerprint_check_step_duration_seconds_count{step=\"whois_fetch\"} ";
        let before = count(&render(), total);
        timed(Step::WhoisFetch, async {
            tokio::time::sleep(Duration::from_millis(30)).await;
        })
        .await;
        let _ = tokio::time::timeout(
            Duration::from_millis(5),
            timed(Step::WhoisFetch, std::future::pending::<()>()),
        )
        .await;
        observe_request(route("/v1/check"), 200, Duration::from_millis(3));
        observe_request(route("/nope"), 503, Duration::from_secs(9));
        let after = render();
        assert!(count(&after, total) >= before + 2);
        let mut previous = 0;
        for le in BOUNDS.iter().map(|b| b.to_string()).chain(["+Inf".into()]) {
            let bucket = format!(
                "openfingerprint_check_step_duration_seconds_bucket{{step=\"whois_fetch\",le=\"{le}\"}} "
            );
            let value = count(&after, &bucket);
            assert!(value >= previous, "buckets are cumulative");
            previous = value;
        }
        assert_eq!(previous, count(&after, total));
        let request = "openfingerprint_http_request_duration_seconds_";
        assert!(
            count(
                &after,
                &format!("{request}count{{route=\"check\",status=\"2xx\"}} ")
            ) >= 1
        );
        let slow = format!("{request}bucket{{route=\"other\",status=\"5xx\",le=\"5\"}} ");
        let all = format!("{request}bucket{{route=\"other\",status=\"5xx\",le=\"+Inf\"}} ");
        assert!(
            count(&after, &all) > count(&after, &slow),
            "a 9s request exceeds every bound"
        );
    }
}
