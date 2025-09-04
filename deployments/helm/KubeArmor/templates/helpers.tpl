{{- define "chart.majorMinorVersion" -}}
{{- $parts := splitList "." .Chart.Version -}}
{{- printf "%s.%s" (index $parts 0) (index $parts 1) -}}
{{- end -}}