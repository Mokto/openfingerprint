# OpenFingerprint Helm chart

Runs the check API and keeps its open domain data fresh, with the Redis it requires
for collection state and the RDAP cache: the bundled `redis-ha` or one you already run.

```sh
helm install openfingerprint oci://ghcr.io/mokto/charts/openfingerprint \
  --namespace openfingerprint --create-namespace \
  --set existingSecret=openfingerprint-config
```

NetworkPolicies are off by default. To isolate the API, enable them and name its callers:

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
| NetworkPolicy `<release>-api` (with `networkPolicy.enabled`) | Ingress only from `networkPolicy.apiFrom` (and `metricsFrom` on the metrics port). Egress only UDP 53 to `networkPolicy.dnsTo` (default: `kube-dns` pods in `kube-system`) for MX and registry-host lookups, TCP 443 to `networkPolicy.rdapTo` (default: public IPv4/IPv6, no private, CGNAT, loopback or link-local ranges) for RDAP, and Redis: the bundled HAProxy pods on 6379, or `networkPolicy.redisTo` on `redisPort`. |
| CronJob `<release>-domain-data` | Every six hours, fetches the pinned public sources and publishes the snapshot to the `<release>-domain-data` ConfigMap. |
| ServiceAccount, Role, RoleBinding | Only the updater gets a token: it may create ConfigMaps and get/patch its own. Kubernetes cannot scope `create` to a name. |
| NetworkPolicy `<release>-domain-data` (with `networkPolicy.enabled`) | The updater accepts nothing; it may reach DNS, HTTPS and `kubeApiServerPorts`. |
| ServiceMonitor, PrometheusRule | Optional dataset-health scraping and alerts. |
| `redis-ha` (default; `redis-ha.enabled`) | The [DandyDeveloper redis-ha](https://github.com/DandyDeveloper/charts/tree/master/charts/redis-ha) chart: three Redis pods with Sentinel and two HAProxy pods, 64 MB, `noeviction`, no persistence or snapshots. Disable it to use your own Redis. |

The API mounts the ConfigMap read-only and reloads it within about two minutes of a
refresh (kubelet sync plus `domainData.reloadSeconds`). Until the first refresh
creates it, domain facts are `unknown`; trigger one immediately after installing:

```sh
kubectl -n openfingerprint create job --from=cronjob/openfingerprint-domain-data initial
```

A rejected snapshot leaves the last valid one serving until its sources expire.
Set `domainData.refresh.enabled=false` to use only the data bundled in the image,
which expires a week after that image's snapshot.

## MX lookups

The API looks up checked domains' MX records through the pod's nameserver, so
callers send only the domain. Its policy allows UDP 53 to `networkPolicy.dnsTo`. If your cluster uses NodeLocal DNSCache or another resolver, set
`dnsTo` to match the pod's `/etc/resolv.conf` nameserver, or lookups report
`unavailable`.
`openfingerprint_mx_lookups_total{result}` counts outcomes.

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

Collection needs one authoritative Redis history ([retention and failover
limits](../README.md#challenge-bound-collection)). `redis-ha` fails over through
Sentinel, which is asynchronous: a failover can lose the latest writes and so bring
back a challenge or event that was already used. If single use must survive Redis
failures, use a Redis whose failover does not lose acknowledged writes. The bundled
instance uses `noeviction`, a 64 MB limit and no persistence; a full Redis rejects new
writes, which fails collection closed and turns RDAP caching off until keys expire.

## Collection state and proxy

Every replica must share the same Redis database and collection settings. If Redis
is unreachable, collection returns 503 and stateless checks keep working.

Keep the Service private. Your application's HTTPS same-origin proxy exposes
only `POST /v1/collect`, preserving Origin, User-Agent and Sec-CH-UA-Platform and
stripping Cookie/Authorization. Do not expose the private challenge/consume routes
or forward browser credentials to them. Include that proxy in `apiFrom`; do not
open ingress to the internet. Add edge quotas for both the proxy and your
application's challenge-issuance route.

See [collection integration and Redis retention](../README.md#challenge-bound-collection).
`/health` checks process liveness, not Redis availability.

## RDAP registration dates

The API asks each domain's registry for its creation date over HTTPS. Registries are
spread across the Internet, so `networkPolicy.rdapTo` allows TCP 443 to every public
address while excluding cluster and private ranges. Narrow it if your CNI supports
FQDN policies. API pods use `ndots: 1`, so registry hostnames skip the cluster
search domains. `openfingerprint_rdap_lookups_total{result}` counts outcomes.

Through Redis, each registered domain reaches its registry at most once a day (an
hour for unregistered ones) across all API replicas. Keys are
`openfingerprint:rdap:v1:` plus a SHA-256 hash of the registered domain, always with
a TTL; values are public registration dates; unavailable answers are not cached. The
API waits at most 250 ms for Redis and falls back to the registry.
`openfingerprint_rdap_cache_total{result}` counts hits, misses and errors.

## Alerts

With `prometheusRule.enabled`:

| Alert | Fires when |
| --- | --- |
| `OpenFingerprintDomainDataUnavailable` | No valid snapshot for 30 minutes, or the metric is missing. |
| `OpenFingerprintDomainSourceExpired` | A source expired; checks report it as stale. |
| `OpenFingerprintDomainSourceExpiring` | A source expires within `expiryWarningDays` (5). For feeds, refreshes have failed for days; reviewed sources need a person to re-review evidence. |
| `OpenFingerprintDomainDataReloadFailing` | The API rejected a changed snapshot in the last hour. |

## Upgrading from a single-file deployment

The Deployment selector is `app.kubernetes.io/name: openfingerprint` plus
`app.kubernetes.io/instance: <release>` and must not change (Kubernetes treats it as
immutable). Updater pods use a different `name` label, so the API's Service and
NetworkPolicy never select them.

## Checks

```sh
bash api/chart/test.sh
```
