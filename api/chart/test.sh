#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -d charts ]; then
  # A throwaway repository config: `helm dependency build` verifies Chart.lock but needs the repo.
  helm_home=$(mktemp -d)
  export HELM_REPOSITORY_CONFIG="$helm_home/repositories.yaml" HELM_REPOSITORY_CACHE="$helm_home/cache"
  helm repo add dandydeveloper https://dandydeveloper.github.io/charts/ >/dev/null
  helm dependency build . >/dev/null
  rm -rf "$helm_home"
  unset HELM_REPOSITORY_CONFIG HELM_REPOSITORY_CACHE
fi
digest=sha256:$(printf 'a%.0s' {1..64})
render() {
  helm template openfingerprint . --namespace openfingerprint \
    --set existingSecret=openfingerprint-config \
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
check.call(pod["securityContext"]["runAsUser"] == 65532 && pod["securityContext"]["runAsNonRoot"], "Non-root API")
check.call(api["securityContext"] == {"readOnlyRootFilesystem" => true, "allowPrivilegeEscalation" => false, "capabilities" => {"drop" => ["ALL"]}}, "API hardening")
check.call(api["image"].end_with?("@sha256:" + "a" * 64) && api["image"].start_with?("ghcr.io/mokto/openfingerprint-api:"), "Pinned API image")
check.call(api["envFrom"] == [{"secretRef" => {"name" => "openfingerprint-config"}}], "Credentials only via the Secret")
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
check.call(plain.(policy["egress"][2]) == {"to" => public, "ports" => [{"protocol" => "TCP", "port" => 443}]}, "RDAP HTTPS preserves its configured peers")
check.call(policy["egress"][3] == {"to" => [{"podSelector" => {"matchLabels" => {"app" => "redis-ha-haproxy", "release" => "openfingerprint"}}}], "ports" => [{"protocol" => "TCP", "port" => 6379}]}, "Redis egress stays scoped to HAProxy")
check.call(pod["dnsConfig"] == {"options" => [{"name" => "ndots", "value" => "1"}]}, "Registry hosts skip cluster search domains")
check.call(policy["ingress"].map { |r| r["ports"] } == [[{"protocol" => "TCP", "port" => 8180}], [{"protocol" => "TCP", "port" => 9180}]], "API and metrics ports only")
check.call(policy["ingress"][0]["from"][0]["podSelector"] == {"matchLabels" => {"app.kubernetes.io/name" => "users"}}, "Configured API callers")
cron = get.call("CronJob")
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
check.call(docs.all? { |d| d["metadata"]["namespace"].nil? || d["metadata"]["namespace"] == "openfingerprint" }, "No foreign namespaces")
puts "Chart selectors, isolation, RBAC, refresh and monitoring checks passed."
' "$rendered"
for empty in dnsTo rdapTo; do
  if render --set-json "networkPolicy.$empty=[]" >/dev/null 2>&1; then echo "An empty $empty must fail" >&2; exit 1; fi
done
minimal=$(helm template openfingerprint . --namespace openfingerprint --set existingSecret=x)
grep -q 'kind: NetworkPolicy' <<< "$minimal" && { echo "NetworkPolicies must be opt-in" >&2; exit 1; }
grep -q 'value: "redis://openfingerprint-redis-ha-haproxy:6379/0"' <<< "$minimal" || { echo "The bundled Redis must be on by default" >&2; exit 1; }
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
own=$(render --set redis-ha.enabled=false --set-json 'networkPolicy.redisTo=[{"podSelector":{"matchLabels":{"app":"redis"}}}]' --set networkPolicy.redisPort=6380)
ruby -ryaml -e '
docs = YAML.load_stream(ARGF.read).compact
abort("Your own Redis must not deploy redis-ha") if docs.any? { |d| d["metadata"]["name"].include?("redis-ha") }
env = docs.find { |d| d["kind"] == "Deployment" }["spec"]["template"]["spec"]["containers"].first["env"].map { |e| e["name"] }
abort("With your own Redis, its URL comes from existingSecret only") if env.any? { |n| n.start_with?("OPENFINGERPRINT_REDIS") }
policy = docs.find { |d| d["kind"] == "NetworkPolicy" && d["metadata"]["name"] == "openfingerprint-api" }["spec"]
expected = {"to" => [{"podSelector" => {"matchLabels" => {"app" => "redis"}}}], "ports" => [{"protocol" => "TCP", "port" => 6380}]}
abort("Redis egress must be scoped to configured peers/port") unless policy["egress"].size == 4 && policy["egress"][3] == expected
puts "Bundled and own Redis checks passed."
' <<< "$own"
if output=$(render --set redis-ha.enabled=false 2>&1) || ! grep -qF "networkPolicy.redisTo must list" <<< "$output"; then
  echo "Policies without redis-ha must require redisTo" >&2; exit 1
fi
static=$(render --set countryData.enabled=false --set domainData.refresh.enabled=false --set redis-ha.enabled=false --set-json 'networkPolicy.redisTo=[{"podSelector":{}}]')
grep -q 'kind: CronJob\|OPENFINGERPRINT_DOMAIN_DATA\|kind: Role\|country-updater\|OPENFINGERPRINT_COUNTRY_DATA' <<< "$static" && { echo "Disabled refresh must render no updater or override" >&2; exit 1; }
render --set countryData.enabled=false > "$rendered"
ruby -ryaml -e '
docs = YAML.load_stream(File.read(ARGV[0])).compact
policy = docs.find { |d| d["kind"] == "NetworkPolicy" && d["metadata"]["name"] == "openfingerprint-api" }["spec"]
abort("Disabled country refresh must retain RDAP and Redis egress") unless policy["egress"].size == 3 && policy["egress"][0]["ports"] == [{"protocol" => "UDP", "port" => 53}]
' "$rendered"
render --set domainData.refresh.enabled=false --set redis-ha.enabled=false --set-json 'networkPolicy.redisTo=[{"podSelector":{}}]' > "$rendered"
ruby -ryaml -e '
docs = YAML.load_stream(File.read(ARGV[0])).compact
pod = docs.find { |d| d["kind"] == "Deployment" }["spec"]["template"]["spec"]
abort("Country refresh must work without domain refresh") unless pod["containers"].size == 2 && pod["volumes"].map { |v| v["name"] } == ["country-data"]
abort("Country updater requires no Kubernetes RBAC") if docs.any? { |d| %w[CronJob Role RoleBinding ServiceAccount].include?(d["kind"]) }
' "$rendered"
for bad in "existingSecret=" "image.digest=invalid" "domainData.refresh.image.digest=sha256:short" "networkPolicy.redisTo=bad" "networkPolicy.redisPort=0" "networkPolicy.redisPort=65536" "networkPolicy.redisPort=6379.5"; do
  if render --set "$bad" >/dev/null 2>&1; then echo "Rendering must fail with $bad" >&2; exit 1; fi
done
if render --set-json 'networkPolicy.apiFrom=[]' >/dev/null 2>&1; then echo "Empty API caller list must fail" >&2; exit 1; fi
helm template openfingerprint . --set existingSecret=x --set networkPolicy.enabled=false | grep -q 'kind: NetworkPolicy' && { echo "Disabled policies must not render" >&2; exit 1; }
helm lint . --strict --set existingSecret=x --set-json 'networkPolicy.apiFrom=[{"podSelector":{}}]' >/dev/null
echo "Disabled refresh, required values and lint checks passed."
