{/*
Expand the name of the chart.
*/}}
{{- define "kubearmor-annotation-manager.name" -}}
{{- default .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "kubearmor-annotation-manager.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Generate certificates for kubearmor-annotaion-manager api server 
*/}}
{{- define "kubearmor-annotation-manager.gen-certs" -}}
{{- $altNames := list ( printf "%s.%s" (include "kubearmor-annotation-manager.name" .) .Values.namespace ) ( printf "%s.%s.svc" (include "kubearmor-annotation-manager.name" .) .Values.namespace ) -}}
{{- $ca := genCA "kubearmor-annotaion-manager-ca" 365 -}}
{{- $cert := genSignedCert ( include "kubearmor-annotation-manager.name" . ) nil $altNames 365 $ca -}}
tls.crt: {{ $cert.Cert | b64enc }}
tls.key: {{ $cert.Key | b64enc }}
{{- end -}}
