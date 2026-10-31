{{- define "ks.labels" -}}
app.kubernetes.io/name: kubeshield
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/part-of: kubeshield
{{- end -}}
{{- define "ks.podSecurity" -}}
runAsNonRoot: true
seccompProfile:
  type: RuntimeDefault
{{- end -}}
{{- define "ks.containerSecurity" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: [ALL]
{{- end -}}
