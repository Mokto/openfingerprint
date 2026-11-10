# OpenFingerprint Helm chart

Documentation: [openfingerprint.com/docs/deploy](https://openfingerprint.com/docs/deploy)

Runs the check API and keeps its open domain and country data fresh, with the Redis
it requires for the RDAP cache and token replay markers: bundled `redis-ha` or your own.
When enabled, NetworkPolicies permit DNS, Redis, registry HTTPS and public HTTPS
for country downloads. Policies apply to the entire pod, not individual containers.
Disable `countryData.enabled` to remove country refresh and its HTTPS allowance;
the RDAP HTTPS allowance remains.

```sh
helm install openfingerprint oci://ghcr.io/mokto/charts/openfingerprint \
  --namespace openfingerprint --create-namespace
```

The API has no authentication, so keep its Service private and isolate it: with the
default `networkPolicy.enabled=false`, any pod in the cluster can call it. Enable the
policies and name its callers:

```sh
  --set networkPolicy.enabled=true \
  --set-json 'networkPolicy.apiFrom=[{"podSelector":{"matchLabels":{"app.kubernetes.io/name":"my-backend"}}}]'
```

Each API release publishes a chart of the same version, pinned to that release's
API and updater image digests.

## What it deploys

| Resource | Purpose |
| --- | --- |
| Deployment and ClusterIP Service | The API on port 80 (container 8180) and, when enabled, metrics on 9180. No Ingress. |
| NetworkPolicy `<release>-api` (with `networkPolicy.enabled`) | Ingress only from `networkPolicy.apiFrom` (and `metricsFrom` on the metrics port). Egress UDP and TCP 53 to `networkPolicy.dnsTo` (default: `kube-dns` pods in `kube-system`) for MX, SPF, DMARC and registry-host lookups (TCP only for answers too large for UDP), TCP 443 and 43 to `networkPolicy.rdapTo` (default: public IPv4/IPv6, no private, CGNAT, loopback or link-local ranges) for RDAP and WHOIS, public TCP 443 for the country and network refresh sidecars when enabled, and Redis: the bundled HAProxy pods on 6379, or `networkPolicy.redisTo` on `redisPort`. |
| CronJob `<release>-domain-data` and `post-install` Job `<release>-domain-data-initial` | Every six hours (and once after install), fetches the pinned public sources and publishes the snapshot to the `<release>-domain-data` ConfigMap. |
| ServiceAccount, Role, RoleBinding | Only the updater gets a token: it may create ConfigMaps and get/patch its own. Kubernetes cannot scope `create` to a name. |
| NetworkPolicy `<release>-domain-data` (with `networkPolicy.enabled`) | The updater accepts nothing; it may reach DNS, HTTPS and `kubeApiServerPorts`. |
| Sidecar `country-updater` and shared `emptyDir` | Downloads DB-IP Country Lite immediately, then daily; retries hourly after failures. Uses the pinned `domainData.refresh.image`, with no credentials or Kubernetes token. |
| Sidecar `network-updater` and per-pod `emptyDir` (with `networkData.sidecar.enabled`) | Runs the pinned `networkData.refresh.image` in `--loop` mode: refreshes network intelligence hourly, retries hourly after failures (every minute until the first manifest exists) and prunes old ASN files. The API mounts the 64Mi volume read-only. No credentials or Kubernetes token. |
| ServiceMonitor, PrometheusRule | Optional domain/country dataset-health scraping and alerts. |
| `redis-ha` (default; `redis-ha.enabled`) | The [DandyDeveloper redis-ha](https://github.com/DandyDeveloper/charts/tree/master/charts/redis-ha) chart: three Redis pods with Sentinel and two HAProxy pods, 64 MB, `noeviction`, no persistence or snapshots. Disable it to use your own Redis. |

The API mounts the ConfigMap read-only and reloads it within about two minutes of a
refresh (kubelet sync plus `domainData.reloadSeconds`). Until the first refresh
creates it, domain facts are `unknown`. A `post-install` hook Job
`<release>-domain-data-initial` runs one refresh right after the first install, so
the snapshot normally exists within a minute. If that Job fails, the install is marked
failed; the cron job still fills the data in. Re-run it manually with
`kubectl -n openfingerprint create job --from=cronjob/openfingerprint-domain-data manual`.

A rejected snapshot leaves the last valid one serving until its sources expire.
Set `domainData.refresh.enabled=false` to use only the data bundled in the image,
which expires a week after that image's snapshot.

## Country data

`countryData.enabled=true` enables local country estimates and automatic refresh.
The API mounts the shared MMDB read-only and checks for changes every minute.
Invalid files and older builds leave the last valid database serving until its
62-day expiry. Country results stay unknown until the first download completes;
download failure never blocks API startup. The bounded `emptyDir` is per pod,
not persistent: restarts download again and each replica refreshes independently.
`countryData.resources` controls the sidecar resources. The API image contains no
country database.

[DB-IP attribution is required](../data/README.md#ip-country-data), including a
link on web pages using the results. Country is a network-location estimate,
not a physical-person location or fraud decision.

## MX lookups

The API looks up checked domains' MX records through the pod's nameserver, so
callers send only the domain. Its policy allows UDP 53 to `networkPolicy.dnsTo`. If your cluster uses NodeLocal DNSCache or another resolver, set
`dnsTo` to match the pod's `/etc/resolv.conf` nameserver, or lookups report
`unavailable`.
`openfingerprint_mx_lookups_total{result}` counts outcomes.

## Scheduling

`onePodPerNode` (default `true`) adds required pod anti-affinity so each node runs at most one API
pod. A rolling update surges one extra pod, so it needs at least `replicaCount + 1` schedulable
nodes; on fewer, set `onePodPerNode=false`. A non-empty `affinity` replaces it.

## Sentry

Set `sentry.dsn` (and optionally `sentry.environment`) to report panics, HTTP 5xx responses
and rejected snapshot reloads. Nothing is sent without a DSN. Events carry no request data;
see the [API guide](../README.md#configuration). With `networkPolicy.enabled`, the default
`rdapTo` already allows public HTTPS; if you narrow it, allow your Sentry ingest host.

## Redis

The API does not start without `OPENFINGERPRINT_REDIS_URL`. By default the chart
deploys `redis-ha` and points the API at its HAProxy Service. With
`redis-ha.auth`, set `redis-ha.existingSecret`; the API reads the password from the
same Secret. Its anti-affinity needs three nodes (set `redis-ha.hardAntiAffinity=false`
on smaller clusters).

To use a Redis or Valkey you already run, set `redis-ha.enabled=false`, add
`OPENFINGERPRINT_REDIS_URL` (and optionally `OPENFINGERPRINT_REDIS_PASSWORD`) to
`existingSecret`, and, with `networkPolicy.enabled`, list its pods in
`networkPolicy.redisTo` with `redisPort` (default 6379). Use the full Service name,
such as `redis://redis.shared.svc.cluster.local:6379/0`: with `ndots: 1`, a short
name is first sent upstream as a public DNS query.

Replay markers need one Redis shared by every replica. `redis-ha` fails over through
Sentinel, which is asynchronous: a failover can lose the latest writes, so a token
checked just before it may not show as replayed afterwards. That only weakens the
`replayed` signal; checks keep working. The bundled instance uses `noeviction`, a 64 MB
limit and no persistence; a full Redis rejects new writes, which leaves `replayed` out
and turns RDAP caching off until keys expire.

## Access

Keep the Service private and name your backend in `networkPolicy.apiFrom`; do not
open ingress to the internet. If a gateway exposes the API, add your own
authentication, quotas and request limits there. The API refuses any request that
carries an `Origin` header, so browsers cannot call it directly.

`/health` checks process liveness, not Redis availability.

## RDAP registration dates

The API asks each domain's registry for its creation date over HTTPS (RDAP) or, for
TLDs without RDAP, over WHOIS on TCP 43. Registries are spread across the Internet,
so `networkPolicy.rdapTo` allows TCP 443 and 43 to every public address while
excluding cluster and private ranges. `openfingerprint_whois_lookups_total{result}`
counts WHOIS outcomes. Narrow it if your CNI supports
FQDN policies. API pods use `ndots: 1`, so registry hostnames skip the cluster
search domains. `openfingerprint_rdap_lookups_total{result}` counts outcomes.

Through Redis, each registered domain reaches its registry at most once a day (an
hour for unregistered ones) across all API replicas. Keys are
`openfingerprint:rdap:v1:` plus a SHA-256 hash of the registered domain, always with
a TTL; values are public registration dates; unavailable answers are not cached. The
API waits at most 250 ms for Redis and falls back to the registry.
`openfingerprint_rdap_cache_total{result}` counts hits, misses and errors.

## Network intelligence

Pick one mode. The first is the default recommendation: it needs no storage class.

**Per-pod sidecar (recommended).** Each API pod runs a `network-updater` sidecar that writes
a pod-local `emptyDir` the API reads. Pods start without waiting on any volume, so storage
failures cannot stall rollouts, and nothing is shared between pods.

```yaml
networkData:
  sidecar:
    enabled: true
```

Network facts are unknown (`data_unavailable`, not a clean result) until the first refresh
publishes, normally within a minute of pod start. Each pod fetches the sources itself, so
sources see one request set per pod per hour, and the pod's NetworkPolicy allows public TCP 443
(the same rule the country sidecar uses, rendered once). The sidecar's memory limit is
per pod (`networkData.sidecar.resources`, default 512Mi). Setting `existingClaim` or
`refresh.enabled` together with the sidecar fails rendering.

**Shared volume with a CronJob.** Kept for clusters with ReadWriteMany storage, where one
refresh serves every replica. Network data then uses an external shared volume, not a
ConfigMap. Provision a PVC writable by UID/group 65532 and readable by every API replica and
the updater. For pods on different nodes this normally requires ReadWriteMany storage with
coherent atomic rename and cross-node file locking. The shared volume's availability becomes a
start-up dependency of every new API pod. The network-data claim must be provisioned
separately.

```yaml
networkData:
  existingClaim: openfingerprint-network-data
  refresh:
    enabled: true
```

In both modes the API mounts the data read-only at `/network-data` and checks `network.json`
every 60 seconds. The CronJob's isolated, non-root network updater writes it hourly, gets no
Kubernetes token/RBAC or server credentials, and has only DNS/HTTPS egress.
The manifest's ASN sidecars must remain in the same directory. Source failures
keep their original expiry and produce a failed/degraded job, not clean results.
No visitor IPs are sent to sources or stored on the volume.

Published charts pin `networkData.refresh.image` (used by both modes) to the matching
`ghcr.io/mokto/openfingerprint-network-updater` digest. For source builds:

```sh
nice -n 15 docker build --target network-updater -f api/Dockerfile \
  -t openfingerprint-network-updater:local .
```

See the [source and licensing guide](../README.md#local-network-intelligence).

An empty `network.json.lock` file is normal: the OS lock, not file existence,
serializes writers and is released on process death. Never delete an active lock
file. Old content-addressed ASN versions may be pruned when no manifest/reader
needs them. Prefer an hourly updater; source expiry is intentionally short for
Tor. The API has no network-dataset fallback or per-request provider calls.

## Alerts

With `prometheusRule.enabled`:

| Alert | Fires when |
| --- | --- |
| `OpenFingerprintDomainDataUnavailable` | No valid snapshot for 30 minutes, or the metric is missing. |
| `OpenFingerprintDomainSourceExpired` | A source expired; checks report it as stale. |
| `OpenFingerprintDomainSourceExpiring` | A source expires within `expiryWarningDays` (5). For feeds, refreshes have failed for days; reviewed sources need a person to re-review evidence. |
| `OpenFingerprintDomainDataReloadFailing` | The API rejected a changed snapshot in the last hour. |
| `OpenFingerprintCountryDataUnavailable` | No country database for 30 minutes, or the metric is missing. |
| `OpenFingerprintCountryDataExpiring` | The database expires within `expiryWarningDays` or has expired. |
| `OpenFingerprintCountryDataReloadFailing` | The API rejected a changed country file in the last hour. |
| `OpenFingerprintRedisErrors` | Redis calls from the registration cache failed for 15 minutes. Registries then get every lookup, and `replayed` is left out. |
| `OpenFingerprintMxLookupsFailing` | Over half of MX lookups were unavailable in 30 minutes (with at least `minLookups`, default 20), for 15 minutes: usually the nameserver or UDP 53 egress. |
| `OpenFingerprintRegistryLookupsFailing` | Over half of RDAP and WHOIS lookups were unavailable in 30 minutes (with at least `minLookups`), for 30 minutes: usually TCP 443/43 egress. |
| `OpenFingerprintNetworkSourceUnavailable` | With the sidecar or a network claim configured, any network source is missing, stale or future-dated for 15 minutes. |
| `OpenFingerprintNetworkDataReloadFailing` | A network reload was rejected in the last hour; last-good sources keep their original expiry. |

## Upgrading from a single-file deployment

The Deployment selector is `app.kubernetes.io/name: openfingerprint` plus
`app.kubernetes.io/instance: <release>` and must not change (Kubernetes treats it as
immutable). Updater pods use a different `name` label, so the API's Service and
NetworkPolicy never select them.

## Checks

```sh
bash api/chart/test.sh
```
