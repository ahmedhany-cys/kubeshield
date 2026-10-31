{{/* Shared spec fragment for every control. Args: dict "mode" "root" */}}
{{- define "ksp.common" -}}
validationActions:
  - {{ if eq .mode "enforce" }}Deny{{ else }}Audit{{ end }}
evaluation:
  admission:
    enabled: true
  background:
    enabled: true
autogen:
  podControllers:
    controllers: [deployments, replicasets, daemonsets, statefulsets, jobs, cronjobs]
matchConstraints:
  namespaceSelector:
    matchLabels:
      kubeshield.io/policy-mode: {{ .mode }}
  resourceRules:
    - apiGroups: [""]
      apiVersions: [v1]
      operations: [CREATE, UPDATE]
      resources: [pods]
variables:
  - name: allContainers
    expression: >-
      object.spec.containers +
      (has(object.spec.initContainers) ? object.spec.initContainers : []) +
      (has(object.spec.ephemeralContainers) ? object.spec.ephemeralContainers : [])
{{- end -}}

{{- define "ksp.meta" -}}
metadata:
  name: ks-{{ .name }}-{{ .mode }}
  labels:
    app.kubernetes.io/part-of: kubeshield
    app.kubernetes.io/managed-by: {{ .root.Release.Service }}
    kubeshield.io/control: {{ .name }}
    kubeshield.io/policy-mode: {{ .mode }}
  annotations:
    kubeshield.io/title: {{ .title | quote }}
    kubeshield.io/severity: {{ .severity | quote }}
    kubeshield.io/remediation: {{ .remediation | quote }}
{{- end -}}
