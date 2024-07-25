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
- name: RELATED_IMAGE_KUBE_RBAC_PROXY
  value: "{{ .repo }}/{{.images.kubeRbacProxy.image}}:{{.images.kubeRbacProxy.tag}}"
{{- end }}

{{- define "operatorImage" }}
{{- if .Values.imagePinning }}
{{- printf "%s/%s:%s" .Values.oci_meta.repo .Values.oci_meta.images.kubearmorOperator.image .Values.oci_meta.images.kubearmorOperator.tag }}
{{- else if eq .Values.kubearmorOperator.image.tag "" }}
{{- printf "%s:%s" .Values.kubearmorOperator.image.repository .Chart.Version }}
{{- else }}
{{- printf "%s:%s" .Values.kubearmorOperator.image.repository .Values.kubearmorOperator.image.tag }}
{{- end }}
{{- end }}

{{- define "generateArgs" }}
{{- if .Values.helm.repository }}
- --repository={{.Values.helm.repository}}
{{- end }}
{{- if .Values.helm.version }}
- --version={{.Values.helm.version}}
{{- end }}
{{- if .Values.helm.directory }}
- --directory={{.Values.helm.directory}}
{{- end }}
{{- if .Values.helm.chart }}
- --chart={{.Values.helm.chart}}
{{- end }}
- --rollbackOnFailure={{.Values.helm.rollbackOnFailure}}
- --skip-crd={{.Values.helm.skipCRD}}
- --snitchImage={{ printf "%s:%s" .Values.snitch.image.repository (default .Chart.Version .Values.snitch.image.tag) }}
- --snitchImagePullPolicy={{ .Values.snitch.imagePullPolicy }}
- --lsmOrder={{ .Values.snitch.lsmOrder }}
{{- end }}