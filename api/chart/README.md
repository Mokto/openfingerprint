# OpenFingerprint Helm chart

Runs the check API and keeps its open domain data fresh. API egress is restricted
to DNS and, when configured, the collection Redis peers.

```sh
helm install openfingerprint oci://ghcr.io/mokto/charts/openfingerprint \
  --namespace openfingerprint --create-namespace \
  --set existingSecret=openfingerprint-config \
  --set-json 'networkPolicy.apiFrom=[{"podSelector":{"matchLabels":{"app.kubernetes.io/name":"my-backend"}}}]'
```

Each API release publishes a chart of the same version, pinned to that release's
API and updater image digests.

## What it deploys

| Resource | Purpose |
| --- | --- |
| Deployment and ClusterIP Service | The API on port 80 (container 8180) and, when enabled, metrics on 9180. No Ingress. |
| NetworkPolicy `<release>-api` | Ingress only from `networkPolicy.apiFrom` (and `metricsFrom` on the metrics port). Egress only UDP 53 to `networkPolicy.dnsTo` (default: `kube-dns` pods in `kube-system`), for MX lookups, plus optional TCP to `networkPolicy.redisTo` on `redisPort`. |
| CronJob `<release>-domain-data` | Every six hours, fetches the pinned public sources and publishes the snapshot to the `<release>-domain-data` ConfigMap. |
| ServiceAccount, Role, RoleBinding | Only the updater gets a token: it may create ConfigMaps and get/patch its own. Kubernetes cannot scope `create` to a name. |
| NetworkPolicy `<release>-domain-data` | The updater accepts nothing; it may reach DNS, HTTPS and `kubeApiServerPorts`. |
| ServiceMonitor, PrometheusRule | Optional dataset-health scraping and alerts. |

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
callers send only the domain. Its policy allows UDP 53 to `networkPolicy.dnsTo` and
optional Redis peers only. If your cluster uses NodeLocal DNSCache or another resolver, set
`dnsTo` to match the pod's `/etc/resolv.conf` nameserver, or lookups report
`unavailable`.
`openfingerprint_mx_lookups_total{result}` counts outcomes.

## Collection state and proxy

To enable challenge-bound collection, add `OPENFINGERPRINT_REDIS_URL` to
`existingSecret` and configure `networkPolicy.redisTo` with the Redis
NetworkPolicy peers and `redisPort` (default 6379). Redis is not deployed by this
chart. Every replica must share the same authoritative database and collection
settings. Without Redis, collection returns 503; stateless checks remain usable.

Keep the Service private. Your application's HTTPS same-origin proxy exposes
only `POST /v1/collect`, preserving Origin, User-Agent and Sec-CH-UA-Platform and
stripping Cookie/Authorization. Do not expose the private challenge/consume routes
or forward browser credentials to them. Include that proxy in `apiFrom`; do not
open ingress to the internet. Add edge quotas for both the proxy and your
application's challenge-issuance route.

See [collection integration and Redis retention](../README.md#challenge-bound-collection).
`/health` checks process liveness, not Redis availability.

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
