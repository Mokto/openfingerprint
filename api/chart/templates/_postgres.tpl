{{- define "of.postgresEnv" -}}
{{- if not (kindIs "bool" .Values.postgres.requireVisitorScope) }}{{ fail "postgres.requireVisitorScope must be a boolean" }}{{ end -}}
{{- if or (not (kindIs "string" .Values.postgres.visitorScope)) (and .Values.postgres.visitorScope (not (regexMatch "^[A-Za-z0-9_-]{1,128}$" .Values.postgres.visitorScope))) }}{{ fail "postgres.visitorScope must be empty or 1-128 ASCII letters, digits, underscores or hyphens" }}{{ end -}}
{{- if and .Values.postgres.requireVisitorScope .Values.postgres.visitorScope }}{{ fail "postgres.visitorScope cannot be set with postgres.requireVisitorScope" }}{{ end -}}
{{- with .Values.postgres.visitorScope }}
- name: OPENFINGERPRINT_VISITOR_SCOPE
  value: {{ . | quote }}
{{- end }}
{{- if .Values.postgres.requireVisitorScope }}
- name: OPENFINGERPRINT_VISITOR_REQUIRE_SCOPE
  value: "true"
{{- end }}
- name: OPENFINGERPRINT_VISITOR_NAMESPACE
  value: {{ required "postgres.namespace is required" .Values.postgres.namespace | quote }}
- name: OPENFINGERPRINT_POSTGRES_URL
  valueFrom:
    secretKeyRef:
      name: {{ required "postgres.existingSecret is required" .Values.postgres.existingSecret | quote }}
      key: {{ .Values.postgres.urlKey | quote }}
{{- with .Values.postgres.passwordKey }}
- name: OPENFINGERPRINT_POSTGRES_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ $.Values.postgres.existingSecret | quote }}
      key: {{ . | quote }}
{{- end }}
{{- if .Values.postgres.caSecret }}
- name: OPENFINGERPRINT_POSTGRES_CA
  value: /postgres-ca/ca.crt
{{- end }}
{{- end }}

{{- define "of.postgresMount" -}}
- name: postgres-ca
  mountPath: /postgres-ca
  readOnly: true
{{- end }}

{{- define "of.postgresVolume" -}}
- name: postgres-ca
  secret:
    secretName: {{ .Values.postgres.caSecret | quote }}
    items:
      - key: {{ .Values.postgres.caKey | quote }}
        path: ca.crt
{{- end }}
