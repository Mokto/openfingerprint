{{- define "of.postgresEnv" -}}
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
