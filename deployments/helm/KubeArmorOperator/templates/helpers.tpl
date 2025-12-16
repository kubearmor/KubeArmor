{{- define "pinnedImages" }}
- name: RELATED_IMAGE_KUBEARMOR_SNITCH
  value: "{{ .repo }}/{{.images.kubearmorSnitch.image}}:{{.images.kubearmorSnitch.tag}}"
- name: RELATED_IMAGE_KUBEARMOR
  value: "{{ .repo }}/{{.images.kubearmor.image}}:{{.images.kubearmor.tag}}"
- name: RELATED_IMAGE_KUBEARMOR_INIT
  value: "{{ .repo }}/{{.images.kubearmorInit.image}}:{{.images.kubearmorInit.tag}}"
- name: RELATED_IMAGE_KUBEARMOR_RELAY_SERVER
  value: "{{ .repo }}/{{.images.kubearmorRelay.image}}:{{.images.kubearmorRelay.tag}}"
- name: RELATED_IMAGE_KUBEARMOR_CONTROLLER
  value: "{{ .repo }}/{{.images.kubearmorController.image}}:{{.images.kubearmorController.tag}}"
{{- end }}

{{- define "operatorImage" }}
{{- if .Values.global.imagePinning }}
{{- printf "%s/%s:%s" .Values.global.kubearmor.repo .Values.global.kubearmor.images.kubearmorOperator.image .Values.global.kubearmor.images.kubearmorOperator.tag }}
{{- else if eq .Values.kubearmorOperator.image.tag "" }}
{{- printf "%s:%s" .Values.kubearmorOperator.image.repository .Chart.Version }}
{{- else }}
{{- printf "%s:%s" .Values.kubearmorOperator.image.repository .Values.kubearmorOperator.image.tag }}
{{- end }}
{{- end }}