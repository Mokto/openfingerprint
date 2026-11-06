{{- define "of.name" -}}
{{- .Release.Name | trunc 40 | trimSuffix "-" -}}
{{- end }}

{{- define "of.labels" -}}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 }}
{{- end }}

{{/* Also the Deployment's immutable selector: never add keys. */}}
{{- define "of.apiSelector" -}}
app.kubernetes.io/name: openfingerprint
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "of.updaterSelector" -}}
app.kubernetes.io/name: openfingerprint-domain-updater
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "of.dataName" -}}
{{ include "of.name" . }}-domain-data
{{- end }}

{{- define "of.image" -}}
{{- $tag := .image.tag | default .appVersion -}}
{{- if .image.digest -}}
{{- if not (regexMatch "^sha256:[0-9a-f]{64}$" .image.digest) }}{{ fail "image digests must be sha256:<64 hex>" }}{{ end -}}
{{ .image.repository }}:{{ $tag }}@{{ .image.digest }}
{{- else -}}
{{ .image.repository }}:{{ $tag }}
{{- end -}}
{{- end }}

{{- define "of.podSecurity" -}}
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
seccompProfile:
  type: RuntimeDefault
{{- end }}

{{- define "of.containerSecurity" -}}
readOnlyRootFilesystem: true
allowPrivilegeEscalation: false
capabilities:
  drop: [ALL]
{{- end }}
