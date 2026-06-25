{{- define "chart.majorMinorVersion" -}}
{{- $parts := splitList "." .Chart.Version -}}
{{- printf "%s.%s" (index $parts 0) (index $parts 1) -}}
{{- end -}}

{{- define "kubearmor.selfProtectionAnnotations" -}}
{{- if .Values.selfProtection.enabled }}
kubearmor.io/self-protection: "enabled"
kubearmor-policy: enabled
{{- else }}
kubearmor-policy: audited
{{- end }}
{{- end -}}
