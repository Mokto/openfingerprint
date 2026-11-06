#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
digest=sha256:$(printf 'a%.0s' {1..64})
render() {
  helm template openfingerprint . --namespace openfingerprint \
    --set existingSecret=openfingerprint-config \
    --set "image.digest=$digest" --set "domainData.refresh.image.digest=$digest" \
    --set-json 'networkPolicy.apiFrom=[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"web"}},"podSelector":{"matchLabels":{"app.kubernetes.io/name":"users"}}}]' \
    --set-json 'networkPolicy.metricsFrom=[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"kube-system"}}}]' \
    --set serviceMonitor.enabled=true --set prometheusRule.enabled=true "$@"
}
rendered=$(mktemp)
trap 'rm -f "$rendered"' EXIT
render > "$rendered"
ruby -ryaml -e '
dup = ->(node) { node.is_a?(Psych::Nodes::Mapping) && (keys = node.children.each_slice(2).map { |k, _| k.value }).uniq.size != keys.size || node.children.to_a.any? { |c| dup.call(c) } }
abort("Rendered YAML repeats a mapping key; strict parsers such as kubeconform reject it") if dup.call(Psych.parse_stream(File.read(ARGV[0])))
docs = YAML.load_stream(File.read(ARGV[0])).compact
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
check.call(env == {"OPENFINGERPRINT_LISTEN_ADDR" => "0.0.0.0:8180", "OPENFINGERPRINT_METRICS_ADDR" => "0.0.0.0:9180", "OPENFINGERPRINT_DOMAIN_DATA" => "/domain-data/domains.json", "OPENFINGERPRINT_DOMAIN_DATA_RELOAD_SECONDS" => "60"}, "API environment")
check.call(pod["volumes"] == [{"name" => "domain-data", "configMap" => {"name" => "openfingerprint-domain-data", "optional" => true}}], "Optional snapshot ConfigMap volume")
check.call(api["volumeMounts"] == [{"name" => "domain-data", "mountPath" => "/domain-data", "readOnly" => true}], "Read-only snapshot mount")
%w[startupProbe readinessProbe livenessProbe].each { |p| check.call(api[p]["httpGet"] == {"path" => "/health", "port" => "http"}, "#{p} uses /health") }
service = get.call("Service")
check.call(service["metadata"]["name"] == "openfingerprint" && service["spec"]["type"] == "ClusterIP", "Stable internal Service name")
check.call(service["spec"]["selector"] == api_labels, "Service selects only API pods")
check.call(service["spec"]["ports"] == [{"name" => "http", "port" => 80, "targetPort" => "http"}, {"name" => "metrics", "port" => 9180, "targetPort" => "metrics"}], "Service ports")
check.call(docs.none? { |d| %w[Ingress IngressRoute].include?(d["kind"]) }, "No public ingress")
policy = get.call("NetworkPolicy", "openfingerprint-api")["spec"]
check.call(policy["podSelector"]["matchLabels"] == api_labels && policy["policyTypes"].sort == %w[Egress Ingress], "API policy isolates both directions")
dns_peer = [{"namespaceSelector" => {"matchLabels" => {"kubernetes.io/metadata.name" => "kube-system"}}, "podSelector" => {"matchLabels" => {"k8s-app" => "kube-dns"}}}]
check.call(policy["egress"] == [{"to" => dns_peer, "ports" => [{"protocol" => "UDP", "port" => 53}]}], "API egress is only MX lookups to cluster DNS on UDP 53")
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
check.call(rules.map { |r| r["alert"] } == %w[OpenFingerprintDomainDataUnavailable OpenFingerprintDomainSourceExpired OpenFingerprintDomainSourceExpiring OpenFingerprintDomainDataReloadFailing], "Alert set")
check.call(rules.all? { |r| r["expr"].include?(%q{namespace="openfingerprint",service="openfingerprint"}) }, "Alerts scoped to this release")
check.call(rules[2]["annotations"]["summary"].include?("{{ $labels.source }}"), "Prometheus templates survive Helm")
check.call(docs.all? { |d| d["metadata"]["namespace"].nil? || d["metadata"]["namespace"] == "openfingerprint" }, "No foreign namespaces")
puts "Chart selectors, isolation, RBAC, refresh and monitoring checks passed."
' "$rendered"
if render --set-json 'networkPolicy.dnsTo=[]' >/dev/null 2>&1; then echo "An empty DNS peer list must fail" >&2; exit 1; fi
static=$(render --set domainData.refresh.enabled=false)
grep -q 'kind: CronJob\|OPENFINGERPRINT_DOMAIN_DATA\|kind: Role' <<< "$static" && { echo "Disabled refresh must render no updater or override" >&2; exit 1; }
for bad in "existingSecret=" "image.digest=invalid" "domainData.refresh.image.digest=sha256:short"; do
  if render --set "$bad" >/dev/null 2>&1; then echo "Rendering must fail with $bad" >&2; exit 1; fi
done
if render --set-json 'networkPolicy.apiFrom=[]' >/dev/null 2>&1; then echo "Empty API caller list must fail" >&2; exit 1; fi
helm template openfingerprint . --set existingSecret=x --set networkPolicy.enabled=false | grep -q 'kind: NetworkPolicy' && { echo "Disabled policies must not render" >&2; exit 1; }
helm lint . --strict --set existingSecret=x --set-json 'networkPolicy.apiFrom=[{"podSelector":{}}]' >/dev/null
echo "Disabled refresh, required values and lint checks passed."
