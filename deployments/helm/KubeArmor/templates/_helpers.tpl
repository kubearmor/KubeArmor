# TODO: handle seccomp

# generate nodeselector labels
{{- define "generateNodeSelectorLabels" -}}
{{- $skipLabel := "arch" -}}
{{- range $key, $value := . }}
{{- if ne $key $skipLabel }}
kubearmor.io/{{ $key }}: {{ $value | quote }}
{{- end }}
{{- end }}
{{- end }}


# template to generate daemonset based on node configuration
{{- define "daemonset.template" -}}
{{- range $index, $element := .Values.nodes }}
{{- if $element }}
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  labels:
    kubearmor-app: kubearmor
  name: kubearmor-{{$element.config.enforcer}}-{{$element.config.runtime}}-{{- trunc 5 (sha256sum $element.config.socket)}}
  namespace: {{$.Release.Namespace}}
spec:
  selector:
    matchLabels:
      kubearmor-app: kubearmor
      {{- include "generateNodeSelectorLabels" $element.config | indent 6 }}
      kubernetes.io/arch: {{ $element.config.arch | quote }}
  template:
    metadata:
      annotations:
        container.apparmor.security.beta.kubernetes.io/kubearmor: unconfined
      labels:
        kubearmor-app: kubearmor
        kubernetes.io/arch: {{ $element.config.arch | quote }}
        {{- include "generateNodeSelectorLabels" $element.config | indent 8}}
    spec:
      containers:
      - args:
        - -gRPC=32767
        {{printf "- -tlsEnabled=%t" $.Values.tls.enabled}}
        {{printf "- -tlsCertPath=%s" $.Values.kubearmor.tls.tlsCertPath}}
        {{printf "- -tlsCertProvider=%s" $.Values.kubearmor.tls.tlsCertProvider}}
        image: {{printf "%s:%s" $.Values.kubearmor.image.repository $.Values.kubearmor.image.tag}}
        imagePullPolicy: {{ $.Values.kubearmor.imagePullPolicy }}
        env:
        - name: KUBEARMOR_NODENAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        - name: KUBEARMOR_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        livenessProbe:
          exec:
            command:
            - /bin/bash
            - -c
            - if [ -z $(pgrep kubearmor) ]; then exit 1; fi;
          initialDelaySeconds: 60
          periodSeconds: 10
        name: kubearmor
        ports:
        - containerPort: 32767
        securityContext:
          capabilities:   
            add:
          {{- if ne $element.config.enforcer "bpf"}}
            - SETUID
            - SETGID
            - SETPCAP
            - MAC_ADMIN
          {{- end }}
            - SYS_ADMIN
            - SYS_PTRACE
            - SYS_RESOURCE
            - IPC_LOCK
            - CAP_DAC_OVERRIDE
            - CAP_DAC_READ_SEARCH
            drop:
            - ALL
          privileged: false
        terminationMessagePath: /dev/termination-log
        terminationMessagePolicy: File
        volumeMounts:
          # common volumeMounts
          {{- toYaml $.Values.volumeMounts.common | trim | nindent 10}}
          # enforcer volumeMount
          {{- if and (eq $element.config.enforcer "apparmor") (eq $element.config.apparmorFs "yes")}}
            {{- toYaml $.Values.volumeMounts.enforcer.apparmor | trim | nindent 10}}
          {{- end }}
          # runtime volumemount
          {{- toYaml (index $.Values.volumeMounts.runtime $element.config.runtime) | trim | nindent 10}}
          # tls volumeMount
          {{- if $.Values.tls.enabled -}}
            {{- toYaml $.Values.kubearmor.tls.kubearmorCACertVolumeMount | trim | nindent 10 }}
          {{- end }}
      dnsPolicy: ClusterFirstWithHostNet
      hostNetwork: true
      hostPID: true
      {{- if eq $element.config.btf "no" }}
      initContainers:
      - image: {{printf "%s:%s" $.Values.kubearmorInit.image.repository $.Values.kubearmorInit.image.tag}}
        imagePullPolicy: {{ $.Values.kubearmorInit.imagePullPolicy }}
        name: init
        securityContext:
          capabilities:
            add:
            - SETUID
            - SETGID
            - SETPCAP
            - MAC_ADMIN
            - SYS_ADMIN
            - SYS_PTRACE
            - SYS_RESOURCE
            - IPC_LOCK
            - CAP_DAC_OVERRIDE
            - CAP_DAC_READ_SEARCH
            drop:
            - ALL
          privileged: false
        volumeMounts:
        {{- toYaml $.Values.volumeMounts.init | trim | nindent 10 }}
      {{- end }}  
      nodeSelector:
        kubernetes.io/os: linux
        kubernetes.io/arch: {{ $element.config.arch | quote }}
        {{- include "generateNodeSelectorLabels" $element.config | nindent 8}}
      restartPolicy: Always
      serviceAccountName: kubearmor
      terminationGracePeriodSeconds: 30
      tolerations:
      - operator: Exists
      volumes:
      # common volume
      {{- toYaml $.Values.volumes.common | trim | nindent 8}}
      # enforcer volume
      {{- if and (eq $element.config.enforcer "apparmor") (eq $element.config.apparmorFs "yes")}}
        {{- toYaml $.Values.volumes.enforcer.apparmor | trim | nindent 8}}
      {{- end }}
      # runtime volume
        - hostPath:
            path: {{printf "/%s" ($element.config.socket | replace "_" "/")}}
            type: Socket
          name: {{$element.config.runtime}}-socket
      # tls volume
      {{- if $.Values.tls.enabled -}}
        {{- toYaml $.Values.kubearmor.tls.kubearmorCACertVolume | trim | nindent 8 }}
      {{- end }}
      # init volume
      {{- if eq $element.config.btf "no" }}
        {{- toYaml $.Values.volumes.init | trim | nindent 8 }}
      {{- end -}}
{{- end }}      
{{- end -}}
{{- end -}}


# template to check if a node is present with apparmor as enforcer
{{- define "hasApparmorEnforcer" -}}
{{- $nodes := index . 0 -}}
{{- $found := false -}}
{{- range $nodes -}}
  {{- if eq .config.enforcer "apparmor" -}}
    {{- $found = true -}}
  {{- end -}}
{{- end -}}
{{- $found -}}
{{- end -}}