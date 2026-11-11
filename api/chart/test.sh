#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -d charts ]; then
  # A throwaway repository config: `helm dependency build` verifies Chart.lock but needs the repo.
  helm_home=$(mktemp -d)
  export HELM_REPOSITORY_CONFIG="$helm_home/repositories.yaml" HELM_REPOSITORY_CACHE="$helm_home/cache"
  helm repo add dandydeveloper https://dandydeveloper.github.io/charts/ >/dev/null
  # GitHub release downloads of the redis-ha tarball intermittently return 504.
  for attempt in 1 2 3 4 5; do
    helm dependency build . >/dev/null && break
    [ "$attempt" -lt 5 ] || exit 1
    sleep $((attempt * 15))
  done
  rm -rf "$helm_home"
  unset HELM_REPOSITORY_CONFIG HELM_REPOSITORY_CACHE
fi
digest=sha256:$(printf 'a%.0s' {1..64})
render() {
  helm template openfingerprint . --namespace openfingerprint \
    --set "image.digest=$digest" --set "domainData.refresh.image.digest=$digest" \
    --set-json 'networkPolicy.apiFrom=[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"web"}},"podSelector":{"matchLabels":{"app.kubernetes.io/name":"users"}}}]' \
    --set-json 'networkPolicy.metricsFrom=[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"kube-system"}}}]' \
    --set networkPolicy.enabled=true --set serviceMonitor.enabled=true --set prometheusRule.enabled=true "$@"
}
rendered=$(mktemp)
trap 'rm -f "$rendered"' EXIT
render > "$rendered"
ruby -ryaml -e '
dup = ->(node) { node.is_a?(Psych::Nodes::Mapping) && (keys = node.children.each_slice(2).map { |k, _| k.value }).uniq.size != keys.size || node.children.to_a.any? { |c| dup.call(c) } }
abort("Rendered YAML repeats a mapping key; strict parsers such as kubeconform reject it") if dup.call(Psych.parse_stream(File.read(ARGV[0])))
docs = YAML.load_stream(File.read(ARGV[0])).compact.reject { |d| d["metadata"]["name"].start_with?("openfingerprint-redis-ha") }
get = ->(kind, name = nil) { docs.find { |d| d["kind"] == kind && (name.nil? || d["metadata"]["name"] == name) } || abort("Missing #{kind} #{name}") }
check = ->(ok, message) { abort(message) unless ok }
api_labels = {"app.kubernetes.io/name" => "openfingerprint", "app.kubernetes.io/instance" => "openfingerprint"}
deployment = get.call("Deployment")
check.call(deployment["spec"]["selector"]["matchLabels"] == api_labels, "Deployment selector is immutable and must stay name+instance")
pod = deployment["spec"]["template"]["spec"]
api = pod["containers"].first
check.call(deployment["spec"]["template"]["metadata"]["labels"] == api_labels, "API pod labels")
check.call(pod["automountServiceAccountToken"] == false, "API gets no Kubernetes token")
check.call(pod["affinity"]["podAntiAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"].first["labelSelector"]["matchLabels"] == api_labels, "One API pod per node")
check.call(pod["securityContext"]["runAsUser"] == 65532 && pod["securityContext"]["runAsNonRoot"], "Non-root API")
check.call(api["securityContext"] == {"readOnlyRootFilesystem" => true, "allowPrivilegeEscalation" => false, "capabilities" => {"drop" => ["ALL"]}}, "API hardening")
check.call(api["image"].end_with?("@sha256:" + "a" * 64) && api["image"].start_with?("ghcr.io/mokto/openfingerprint-api:"), "Pinned API image")
check.call(api["envFrom"].nil?, "The API needs no Secret with the bundled Redis")
env = api["env"].to_h { |e| [e["name"], e["value"]] }
check.call(env == {"OPENFINGERPRINT_LISTEN_ADDR" => "0.0.0.0:8180", "OPENFINGERPRINT_METRICS_ADDR" => "0.0.0.0:9180", "OPENFINGERPRINT_DOMAIN_DATA" => "/domain-data/domains.json", "OPENFINGERPRINT_DOMAIN_DATA_RELOAD_SECONDS" => "60", "OPENFINGERPRINT_REDIS_URL" => "redis://openfingerprint-redis-ha-haproxy:6379/0", "OPENFINGERPRINT_COUNTRY_DATA" => "/country-data/country.mmdb"}, "API environment")
check.call(pod["volumes"] == [{"name" => "country-data", "emptyDir" => {"sizeLimit" => "96Mi"}}, {"name" => "domain-data", "configMap" => {"name" => "openfingerprint-domain-data", "optional" => true}}], "Country emptyDir and optional domain ConfigMap")
check.call(api["volumeMounts"] == [{"name" => "domain-data", "mountPath" => "/domain-data", "readOnly" => true}, {"name" => "country-data", "mountPath" => "/country-data", "readOnly" => true}], "Read-only data mounts")
country = pod["containers"].find { |c| c["name"] == "country-updater" }
check.call(country["command"] == ["/nodejs/bin/node", "/app/update-country-data.mjs"] && country["args"] == ["--output", "/country-data/country.mmdb", "--loop"], "Country refresh loop")
check.call(country["image"].end_with?("@sha256:" + "a" * 64), "Pinned country updater")
check.call(country["envFrom"].nil? && country["env"].nil?, "Country updater gets no credentials")
check.call(country["volumeMounts"] == [{"name" => "country-data", "mountPath" => "/country-data"}] && pod["securityContext"]["fsGroup"] == 65532, "Country updater can write its own volume only")
check.call(country["securityContext"] == api["securityContext"], "Country updater hardening")
%w[startupProbe readinessProbe livenessProbe].each { |p| check.call(api[p]["httpGet"] == {"path" => "/health", "port" => "http"}, "#{p} uses /health") }
service = get.call("Service")
check.call(service["metadata"]["name"] == "openfingerprint" && service["spec"]["type"] == "ClusterIP", "Stable internal Service name")
check.call(service["spec"]["selector"] == api_labels, "Service selects only API pods")
check.call(service["spec"]["ports"] == [{"name" => "http", "port" => 80, "targetPort" => "http"}, {"name" => "metrics", "port" => 9180, "targetPort" => "metrics"}], "Service ports")
check.call(docs.none? { |d| %w[Ingress IngressRoute].include?(d["kind"]) }, "No public ingress")
policy = get.call("NetworkPolicy", "openfingerprint-api")["spec"]
check.call(policy["podSelector"]["matchLabels"] == api_labels && policy["policyTypes"].sort == %w[Egress Ingress], "API policy isolates both directions")
dns_peer = [{"namespaceSelector" => {"matchLabels" => {"kubernetes.io/metadata.name" => "kube-system"}}, "podSelector" => {"matchLabels" => {"k8s-app" => "kube-dns"}}}]
public = [{"ipBlock" => {"cidr" => "0.0.0.0/0", "except" => %w[10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16]}}, {"ipBlock" => {"cidr" => "::/0", "except" => %w[fc00::/7 fe80::/10]}}]
# Psych reads the unquoted "::/0" as a Symbol; Kubernetes reads a string.
plain = ->(x) { x.is_a?(Hash) ? x.transform_values { |v| plain.(v) } : x.is_a?(Array) ? x.map { |v| plain.(v) } : x.is_a?(Symbol) ? ":#{x}" : x }
check.call(policy["egress"][0] == {"to" => dns_peer, "ports" => [{"protocol" => "UDP", "port" => 53}, {"protocol" => "TCP", "port" => 53}]}, "Country refresh DNS supports TCP fallback")
https = policy["egress"][1]
check.call(policy["egress"].size == 4 && https["ports"] == [{"protocol" => "TCP", "port" => 443}], "Country updater HTTPS only")
check.call(https["to"] == [{"ipBlock" => {"cidr" => "0.0.0.0/0", "except" => %w[0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4]}}, {"ipBlock" => {"cidr" => "2000::/3"}}], "Country HTTPS excludes private, loopback and link-local targets")
check.call(plain.(policy["egress"][2]) == {"to" => public, "ports" => [{"protocol" => "TCP", "port" => 443}, {"protocol" => "TCP", "port" => 43}]}, "Registries: RDAP over HTTPS and WHOIS on 43, to the configured peers only")
check.call(policy["egress"][3] == {"to" => [{"podSelector" => {"matchLabels" => {"app" => "redis-ha-haproxy", "release" => "openfingerprint"}}}], "ports" => [{"protocol" => "TCP", "port" => 6379}]}, "Redis egress stays scoped to HAProxy")
check.call(pod["dnsConfig"] == {"options" => [{"name" => "ndots", "value" => "1"}]}, "Registry hosts skip cluster search domains")
check.call(policy["ingress"].map { |r| r["ports"] } == [[{"protocol" => "TCP", "port" => 8180}], [{"protocol" => "TCP", "port" => 9180}]], "API and metrics ports only")
check.call(policy["ingress"][0]["from"][0]["podSelector"] == {"matchLabels" => {"app.kubernetes.io/name" => "users"}}, "Configured API callers")
cron = get.call("CronJob")
hook = get.call("Job", "openfingerprint-domain-data-initial")
check.call(hook["metadata"]["annotations"]["helm.sh/hook"] == "post-install" && hook["spec"]["template"] == cron["spec"]["jobTemplate"]["spec"]["template"], "Initial refresh hook runs the cron pod")
job = cron["spec"]["jobTemplate"]["spec"]["template"]
updater_labels = job["metadata"]["labels"]
check.call(updater_labels == {"app.kubernetes.io/name" => "openfingerprint-domain-updater", "app.kubernetes.io/instance" => "openfingerprint"}, "Updater labels")
check.call(!api_labels.all? { |k, v| updater_labels[k] == v }, "API Service/policy must never select updater pods")
check.call(cron["spec"]["concurrencyPolicy"] == "Forbid", "One refresh at a time")
updater = job["spec"]["containers"].first
check.call(job["spec"]["serviceAccountName"] == "openfingerprint-domain-data" && job["spec"]["automountServiceAccountToken"] == true, "Only the updater gets a token")
check.call(updater["args"] == ["--configmap", "openfingerprint-domain-data"], "Updater writes the mounted ConfigMap")
check.call(updater["env"] == [{"name" => "NODE_EXTRA_CA_CERTS", "value" => "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"}], "Updater trusts the cluster CA")
check.call(updater["image"].start_with?("ghcr.io/mokto/openfingerprint-domain-updater:") && updater["image"].end_with?("@sha256:" + "a" * 64), "Pinned updater image")
check.call(updater["securityContext"]["readOnlyRootFilesystem"] == true, "Read-only updater")
check.call(get.call("ServiceAccount")["automountServiceAccountToken"] == false, "No default token mounting for the account")
check.call(get.call("Role")["rules"] == [{"apiGroups" => [""], "resources" => ["configmaps"], "verbs" => ["create"]}, {"apiGroups" => [""], "resources" => ["configmaps"], "resourceNames" => ["openfingerprint-domain-data"], "verbs" => ["get", "patch"]}], "Updater RBAC is limited to its ConfigMap")
updater_policy = get.call("NetworkPolicy", "openfingerprint-domain-data")["spec"]
check.call(updater_policy["podSelector"]["matchLabels"] == updater_labels && updater_policy["ingress"] == [], "Updater accepts no connections")
check.call(updater_policy["egress"].flat_map { |r| r["ports"].map { |p| [p["protocol"], p["port"]] } } == [["UDP", 53], ["TCP", 53], ["TCP", 443], ["TCP", 6443]], "Updater egress: DNS, HTTPS, Kubernetes API")
check.call(get.call("ServiceMonitor")["spec"]["endpoints"] == [{"port" => "metrics", "interval" => "60s"}], "ServiceMonitor scrapes metrics")
rules = get.call("PrometheusRule")["spec"]["groups"][0]["rules"]
check.call(rules.map { |r| r["alert"] } == %w[OpenFingerprintDomainDataUnavailable OpenFingerprintDomainSourceExpired OpenFingerprintDomainSourceExpiring OpenFingerprintDomainDataReloadFailing OpenFingerprintCountryDataUnavailable OpenFingerprintCountryDataExpiring OpenFingerprintCountryDataReloadFailing], "Alert set")
check.call(rules.all? { |r| r["expr"].include?(%q{namespace="openfingerprint",service="openfingerprint"}) }, "Alerts scoped to this release")
check.call(rules[2]["annotations"]["summary"].include?("{{ $labels.source }}"), "Prometheus templates survive Helm")
lookups = get.call("PrometheusRule")["spec"]["groups"][1]
check.call(lookups["name"] == "openfingerprint-lookups" && lookups["rules"].map { |r| r["alert"] } == %w[OpenFingerprintRedisErrors OpenFingerprintMxLookupsFailing OpenFingerprintRegistryLookupsFailing], "Lookup health alerts")
check.call(lookups["rules"].all? { |r| r["expr"].scan(/\{[^}]*\}/).reject { |m| m.include?("$value") }.all? { |m| m.include?(%q{namespace="openfingerprint",service="openfingerprint"}) } }, "Every lookup alert selector is scoped to this release")
check.call(lookups["rules"][1]["expr"].include?(">= 20"), "Lookup alerts ignore low volume")
check.call(docs.all? { |d| d["metadata"]["namespace"].nil? || d["metadata"]["namespace"] == "openfingerprint" }, "No foreign namespaces")
puts "Chart selectors, isolation, RBAC, refresh and monitoring checks passed."
' "$rendered"
for empty in dnsTo rdapTo; do
  if render --set-json "networkPolicy.$empty=[]" >/dev/null 2>&1; then echo "An empty $empty must fail" >&2; exit 1; fi
done
minimal=$(helm template openfingerprint . --namespace openfingerprint)
grep -q 'kind: NetworkPolicy' <<< "$minimal" && { echo "NetworkPolicies must be opt-in" >&2; exit 1; }
grep -q 'value: "redis://openfingerprint-redis-ha-haproxy:6379/0"' <<< "$minimal" || { echo "The bundled Redis must be on by default" >&2; exit 1; }
sentry=$(render --set sentry.dsn=https://k@sentry.example/1 --set sentry.environment=prod)
grep -q 'name: SENTRY_DSN' <<< "$sentry" && grep -q 'value: "prod"' <<< "$sentry" || { echo "sentry values must reach the API" >&2; exit 1; }
bundled=$(render --set redis-ha.auth=true --set redis-ha.existingSecret=cache-auth)
ruby -ryaml -e '
docs = YAML.load_stream(ARGF.read).compact
api = docs.find { |d| d["kind"] == "Deployment" && d["metadata"]["name"] == "openfingerprint" }["spec"]["template"]["spec"]["containers"].first
env = api["env"].to_h { |e| [e["name"], e["value"] || e["valueFrom"]] }
abort("API must use the redis-ha HAProxy service") unless env["OPENFINGERPRINT_REDIS_URL"] == "redis://openfingerprint-redis-ha-haproxy:6379/0"
abort("API must read the Redis password from the redis-ha Secret") unless env["OPENFINGERPRINT_REDIS_PASSWORD"] == {"secretKeyRef" => {"name" => "cache-auth", "key" => "auth"}}
docs.find { |d| d["kind"] == "Service" && d["metadata"]["name"] == "openfingerprint-redis-ha-haproxy" } or abort("Missing HAProxy Service")
haproxy = docs.find { |d| d["kind"] == "Deployment" && d["metadata"]["name"] == "openfingerprint-redis-ha-haproxy" }["spec"]["template"]["metadata"]["labels"]
egress = docs.find { |d| d["kind"] == "NetworkPolicy" && d["metadata"]["name"] == "openfingerprint-api" }["spec"]["egress"].last
abort("API egress to Redis must select the HAProxy pods on 6379") unless egress["ports"] == [{"protocol" => "TCP", "port" => 6379}] && egress["to"].first["podSelector"]["matchLabels"].all? { |k, v| haproxy[k] == v }
config = docs.find { |d| d["kind"] == "ConfigMap" && d["metadata"]["name"] == "openfingerprint-redis-ha-configmap" }["data"]["redis.conf"]
abort("Bundled Redis: bounded memory, no eviction of collection state, no snapshots") unless config.include?("maxmemory 64mb") && config.include?("maxmemory-policy noeviction") && config.include?(%q{save ""})
abort("No persistent volumes") if docs.any? { |d| d["kind"] == "StatefulSet" && d["spec"]["volumeClaimTemplates"] }
' <<< "$bundled"
own=$(render --set redis-ha.enabled=false --set existingSecret=redis-url --set-json 'networkPolicy.redisTo=[{"podSelector":{"matchLabels":{"app":"redis"}}}]' --set networkPolicy.redisPort=6380)
ruby -ryaml -e '
docs = YAML.load_stream(ARGF.read).compact
abort("Your own Redis must not deploy redis-ha") if docs.any? { |d| d["metadata"]["name"].include?("redis-ha") }
env = docs.find { |d| d["kind"] == "Deployment" }["spec"]["template"]["spec"]["containers"].first["env"].map { |e| e["name"] }
abort("With your own Redis, its URL comes from existingSecret only") if env.any? { |n| n.start_with?("OPENFINGERPRINT_REDIS") }
envFrom = docs.find { |d| d["kind"] == "Deployment" }["spec"]["template"]["spec"]["containers"].first["envFrom"]
abort("The Secret must be loaded into the API") unless envFrom == [{"secretRef" => {"name" => "redis-url"}}]
policy = docs.find { |d| d["kind"] == "NetworkPolicy" && d["metadata"]["name"] == "openfingerprint-api" }["spec"]
expected = {"to" => [{"podSelector" => {"matchLabels" => {"app" => "redis"}}}], "ports" => [{"protocol" => "TCP", "port" => 6380}]}
abort("Redis egress must be scoped to configured peers/port") unless policy["egress"].size == 4 && policy["egress"][3] == expected
puts "Bundled and own Redis checks passed."
' <<< "$own"
if output=$(render --set redis-ha.enabled=false --set existingSecret=redis-url 2>&1) || ! grep -qF "networkPolicy.redisTo must list" <<< "$output"; then
  echo "Policies without redis-ha must require redisTo" >&2; exit 1
fi
static=$(render --set countryData.enabled=false --set domainData.refresh.enabled=false --set redis-ha.enabled=false --set existingSecret=redis-url --set-json 'networkPolicy.redisTo=[{"podSelector":{}}]')
grep -q 'kind: CronJob\|OPENFINGERPRINT_DOMAIN_DATA\|kind: Role\|country-updater\|OPENFINGERPRINT_COUNTRY_DATA' <<< "$static" && { echo "Disabled refresh must render no updater or override" >&2; exit 1; }
render --set countryData.enabled=false > "$rendered"
ruby -ryaml -e '
docs = YAML.load_stream(File.read(ARGV[0])).compact
policy = docs.find { |d| d["kind"] == "NetworkPolicy" && d["metadata"]["name"] == "openfingerprint-api" }["spec"]
abort("Disabled country refresh must retain DNS (UDP and TCP), RDAP and Redis egress") unless policy["egress"].size == 3 && policy["egress"][0]["ports"] == [{"protocol" => "UDP", "port" => 53}, {"protocol" => "TCP", "port" => 53}]
' "$rendered"
render --set domainData.refresh.enabled=false --set redis-ha.enabled=false --set existingSecret=redis-url --set-json 'networkPolicy.redisTo=[{"podSelector":{}}]' > "$rendered"
ruby -ryaml -e '
docs = YAML.load_stream(File.read(ARGV[0])).compact
pod = docs.find { |d| d["kind"] == "Deployment" }["spec"]["template"]["spec"]
abort("Country refresh must work without domain refresh") unless pod["containers"].size == 2 && pod["volumes"].map { |v| v["name"] } == ["country-data"]
abort("Country updater requires no Kubernetes RBAC") if docs.any? { |d| %w[CronJob Role RoleBinding ServiceAccount].include?(d["kind"]) }
' "$rendered"
if render --set networkData.refresh.enabled=true >/dev/null 2>&1; then echo "Network refresh requires a shared claim" >&2; exit 1; fi
render --set networkData.existingClaim=network-data --set networkData.refresh.enabled=true --set "networkData.refresh.image.digest=$digest" > "$rendered"
ruby -ryaml -e '
docs = YAML.load_stream(File.read(ARGV[0])).compact
pod = docs.find { |d| d["kind"] == "Deployment" && d["metadata"]["name"] == "openfingerprint" }["spec"]["template"]["spec"]
api = pod["containers"][0]
abort("API must mount shared network data read-only") unless api["volumeMounts"].include?({"name"=>"network-data","mountPath"=>"/network-data","readOnly"=>true})
abort("Network manifest path missing") unless api["env"].include?({"name"=>"OPENFINGERPRINT_NETWORK_DATA","value"=>"/network-data/network.json"})
abort("Wrong shared claim") unless pod["volumes"].include?({"name"=>"network-data","persistentVolumeClaim"=>{"claimName"=>"network-data"}})
cron = docs.find { |d| d["kind"] == "CronJob" && d["metadata"]["name"] == "openfingerprint-network-data" }
job = cron["spec"]["jobTemplate"]["spec"]["template"]
updater = job["spec"]["containers"][0]
abort("Network updater must have no service-account token") unless job["spec"]["automountServiceAccountToken"] == false
abort("Writer must be non-root with volume group permissions") unless job["spec"]["securityContext"]["runAsUser"] == 65532 && job["spec"]["securityContext"]["fsGroup"] == 65532
abort("Network updater isolation") unless cron["spec"]["concurrencyPolicy"] == "Forbid" && updater["securityContext"]["readOnlyRootFilesystem"] && updater["args"] == ["--output","/network-data/network.json"]
abort("Pinned network updater image missing") unless updater["image"].start_with?("ghcr.io/mokto/openfingerprint-network-updater:") && updater["image"].end_with?("@sha256:" + "a"*64)
policy = docs.find { |d| d["kind"] == "NetworkPolicy" && d["metadata"]["name"] == "openfingerprint-network-data" }["spec"]
abort("Network updater policy must select only updater pods") unless policy["podSelector"]["matchLabels"] == job["metadata"]["labels"] && policy["ingress"] == []
abort("Only DNS and HTTPS egress") unless policy["egress"].flat_map { |r| r["ports"].map { |p| [p["protocol"],p["port"]] } } == [["UDP",53],["TCP",53],["TCP",443]]
groups = docs.find { |d| d["kind"] == "PrometheusRule" }["spec"]["groups"]
abort("Network alerts missing") unless groups.any? { |g| g["name"] == "openfingerprint-network-data" && g["rules"].size == 2 }
puts "Shared network volume, isolated refresh and freshness alerts passed."
' "$rendered"
for conflict in "networkData.existingClaim=network-data" "networkData.refresh.enabled=true"; do
  if render --set networkData.sidecar.enabled=true --set "$conflict" >/dev/null 2>&1; then echo "Network sidecar must reject $conflict" >&2; exit 1; fi
done
for variant in "" "countryData.enabled=false"; do
  render --set networkData.sidecar.enabled=true --set "networkData.refresh.image.digest=$digest" ${variant:+--set "$variant"} > "$rendered"
  VARIANT="$variant" ruby -ryaml -e '
docs = YAML.load_stream(File.read(ARGV[0])).compact.reject { |d| d["metadata"]["name"].start_with?("openfingerprint-redis-ha") }
pod = docs.find { |d| d["kind"] == "Deployment" }["spec"]["template"]["spec"]
api = pod["containers"][0]
sidecar = pod["containers"].find { |c| c["name"] == "network-updater" } || abort("Network sidecar missing")
abort("API reads the manifest") unless api["env"].include?({"name"=>"OPENFINGERPRINT_NETWORK_DATA","value"=>"/network-data/network.json"})
abort("API must mount network data read-only") unless api["volumeMounts"].include?({"name"=>"network-data","mountPath"=>"/network-data","readOnly"=>true})
abort("Sidecar must write only its own volume") unless sidecar["volumeMounts"] == [{"name"=>"network-data","mountPath"=>"/network-data"}]
abort("Per-pod emptyDir only, no PVC") unless pod["volumes"].select { |v| v["name"] == "network-data" } == [{"name"=>"network-data","emptyDir"=>{"sizeLimit"=>"64Mi"}}] && pod["volumes"].none? { |v| v["persistentVolumeClaim"] }
abort("Sidecar loop") unless sidecar["args"] == ["--output","/network-data/network.json","--loop"] && sidecar["command"].nil?
abort("Pinned network updater image") unless sidecar["image"].start_with?("ghcr.io/mokto/openfingerprint-network-updater:") && sidecar["image"].end_with?("@sha256:" + "a"*64)
abort("Sidecar hardening") unless sidecar["securityContext"] == {"readOnlyRootFilesystem"=>true,"allowPrivilegeEscalation"=>false,"capabilities"=>{"drop"=>["ALL"]}} && sidecar["securityContext"] == api["securityContext"]
abort("Sidecar gets no credentials") unless sidecar["env"].nil? && sidecar["envFrom"].nil?
abort("No Kubernetes token") unless pod["automountServiceAccountToken"] == false
abort("Non-root with volume group") unless pod["securityContext"]["runAsUser"] == 65532 && pod["securityContext"]["runAsNonRoot"] && pod["securityContext"]["fsGroup"] == 65532
abort("No shared-volume resources in sidecar mode") if docs.any? { |d| d["kind"] == "PersistentVolumeClaim" || (d["kind"] == "CronJob" && d["metadata"]["name"] == "openfingerprint-network-data") }
abort("No network CronJob policy") if docs.any? { |d| d["kind"] == "NetworkPolicy" && d["metadata"]["name"] == "openfingerprint-network-data" }
public = docs.find { |d| d["kind"] == "NetworkPolicy" && d["metadata"]["name"] == "openfingerprint-api" }["spec"]["egress"].select { |r| r["ports"] == [{"protocol"=>"TCP","port"=>443}] && r["to"].first["ipBlock"]["cidr"] == "0.0.0.0/0" && r["to"].last == {"ipBlock"=>{"cidr"=>"2000::/3"}} }
abort("Public HTTPS egress must be allowed exactly once, TCP 443 only") unless public.size == 1
abort("API policy must stay narrow") unless docs.find { |d| d["kind"] == "NetworkPolicy" && d["metadata"]["name"] == "openfingerprint-api" }["spec"]["egress"].flat_map { |r| r["ports"].map { |p| p["port"] } }.uniq.sort == [43, 53, 443, 6379]
groups = docs.find { |d| d["kind"] == "PrometheusRule" }["spec"]["groups"]
abort("Network alerts missing") unless groups.any? { |g| g["name"] == "openfingerprint-network-data" && g["rules"].map { |r| r["alert"] } == %w[OpenFingerprintNetworkSourceUnavailable OpenFingerprintNetworkDataReloadFailing] }
' "$rendered"
done
if grep -q 'network-updater' <<< "$(render)"; then echo "Network sidecar must be opt-in" >&2; exit 1; fi
echo "Per-pod network sidecar, egress, isolation and alerts passed."
grep -q 'collect' <<< "$(render)" && { echo "The collection listener must be opt-in" >&2; exit 1; }
render --set collect.enabled=true --set collect.proxyProtocol=true \
  --set-json 'collect.origins=["https://app.example.com","https://www.example.com"]' \
  --set-json 'collect.certificates=[{"host":"c.example.com","secretName":"c-tls"},{"host":"c.example.org","secretName":"org-tls"}]' \
  --set-json 'networkPolicy.collectFrom=[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"traefik"}}}]' > "$rendered"
ruby -ryaml -e '
docs = YAML.load_stream(File.read(ARGV[0])).compact.reject { |d| d["metadata"]["name"].start_with?("openfingerprint-redis-ha") }
pod = docs.find { |d| d["kind"] == "Deployment" }["spec"]["template"]["spec"]
api = pod["containers"][0]
env = api["env"].to_h { |e| [e["name"], e["value"]] }
abort("Collection environment") unless env.values_at("OPENFINGERPRINT_COLLECT_ADDR", "OPENFINGERPRINT_COLLECT_CERTS", "OPENFINGERPRINT_COLLECT_ORIGINS", "OPENFINGERPRINT_COLLECT_PROXY_PROTOCOL") == ["0.0.0.0:8443", "/collect-certs", "https://app.example.com,https://www.example.com", "true"]
abort("Collection port") unless api["ports"].include?({"name" => "collect", "containerPort" => 8443})
abort("Certificates mount read-only") unless api["volumeMounts"].include?({"name" => "collect-certs", "mountPath" => "/collect-certs", "readOnly" => true})
sources = pod["volumes"].find { |v| v["name"] == "collect-certs" }["projected"]["sources"]
abort("One directory per hostname") unless sources == [["c-tls", "c.example.com"], ["org-tls", "c.example.org"]].map { |name, host| {"secret" => {"name" => name, "items" => [{"key" => "tls.crt", "path" => "#{host}/tls.crt"}, {"key" => "tls.key", "path" => "#{host}/tls.key"}]}} }
main = docs.find { |d| d["kind"] == "Service" && d["metadata"]["name"] == "openfingerprint" }
abort("The private Service must not expose the collection port") if main["spec"]["ports"].any? { |p| p["name"] == "collect" }
collect = docs.find { |d| d["kind"] == "Service" && d["metadata"]["name"] == "openfingerprint-collect" } || abort("Missing collection Service")
abort("Collection Service") unless collect["spec"]["type"] == "ClusterIP" && collect["spec"]["ports"] == [{"name" => "collect", "port" => 443, "targetPort" => "collect"}] && collect["spec"]["selector"] == main["spec"]["selector"]
abort("The ServiceMonitor must not select the collection Service") if collect["metadata"]["labels"]["app.kubernetes.io/name"] == "openfingerprint"
ingress = docs.find { |d| d["kind"] == "NetworkPolicy" && d["metadata"]["name"] == "openfingerprint-api" }["spec"]["ingress"]
abort("Collection port open to collectFrom only") unless ingress.map { |r| r["ports"] } == [[{"protocol" => "TCP", "port" => 8180}], [{"protocol" => "TCP", "port" => 8443}], [{"protocol" => "TCP", "port" => 9180}]] && ingress[1]["from"] == [{"namespaceSelector" => {"matchLabels" => {"kubernetes.io/metadata.name" => "traefik"}}}]
groups = docs.find { |d| d["kind"] == "PrometheusRule" }["spec"]["groups"]
abort("Certificate reload alert") unless groups.any? { |g| g["name"] == "openfingerprint-collect" && g["rules"].map { |r| r["alert"] } == ["OpenFingerprintCollectCertificateReloadFailing"] }
' "$rendered"
collect=(--set collect.enabled=true --set-json 'collect.origins=["*"]' --set-json 'collect.certificates=[{"host":"c.example.com","secretName":"c-tls"}]' --set-json 'networkPolicy.collectFrom=[{"podSelector":{}}]')
for bad in 'collect.origins=[]' 'collect.certificates=[]' 'collect.certificates=[{"host":"../etc","secretName":"c-tls"}]' 'collect.certificates=[{"host":"c.example.com"}]' 'networkPolicy.collectFrom=[]'; do
  if render "${collect[@]}" --set-json "$bad" >/dev/null 2>&1; then echo "Rendering must fail with $bad" >&2; exit 1; fi
done
lb=$(render "${collect[@]}" --set collect.service.type=LoadBalancer --set-json 'collect.service.annotations={"load-balancer.hetzner.cloud/uses-proxyprotocol":"true"}')
grep -q 'load-balancer.hetzner.cloud/uses-proxyprotocol: "true"' <<< "$lb" && grep -q 'type: LoadBalancer' <<< "$lb" || { echo "Collection Service type and annotations" >&2; exit 1; }
echo "Opt-in collection listener, certificates, separate Service, ingress policy and alert passed."
for bad in "redis-ha.enabled=false" "image.digest=invalid" "domainData.refresh.image.digest=sha256:short" "networkPolicy.redisTo=bad" "networkPolicy.redisPort=0" "networkPolicy.redisPort=65536" "networkPolicy.redisPort=6379.5"; do
  if render --set "$bad" >/dev/null 2>&1; then echo "Rendering must fail with $bad" >&2; exit 1; fi
done
if render --set-json 'networkPolicy.apiFrom=[]' >/dev/null 2>&1; then echo "Empty API caller list must fail" >&2; exit 1; fi
helm template openfingerprint . --set networkPolicy.enabled=false | grep -q 'kind: NetworkPolicy' && { echo "Disabled policies must not render" >&2; exit 1; }
helm lint . --strict --set-json 'networkPolicy.apiFrom=[{"podSelector":{}}]' >/dev/null
echo "Disabled refresh, required values and lint checks passed."
