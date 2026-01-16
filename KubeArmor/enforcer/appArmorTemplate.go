// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package enforcer

// ProfileHeader contain sAppArmor Profile/SubProfile header config
type ProfileHeader struct {
	File, Network, Capabilities, Privileged bool
}

// Init sets the presence of Entity headers to true by default
func (h *ProfileHeader) Init() {
	h.File = true
	h.Network = true
	h.Capabilities = true
	h.Privileged = false
}

// RuleConfig contains details for individual apparmor rules
type RuleConfig struct {
	Dir, Recursive, ReadOnly, OwnerOnly, Deny, Allow bool
}

// Rules contains configuration for the AppArmor Profile/SubProfile Body
type Rules struct {
	FilePaths         map[string]RuleConfig
	ProcessPaths      map[string]RuleConfig
	NetworkRules      map[string]RuleConfig
	CapabilitiesRules map[string]RuleConfig
}

// Init initialises elements Rule Structure
func (r *Rules) Init() {
	r.FilePaths = make(map[string]RuleConfig)
	r.ProcessPaths = make(map[string]RuleConfig)
	r.NetworkRules = make(map[string]RuleConfig)
	r.CapabilitiesRules = make(map[string]RuleConfig)
}

// FromSourceConfig has details for individual from source subprofiles
type FromSourceConfig struct {
	Fusion bool
	ProfileHeader
	Rules
}

// Profile header has all the details for a new AppArmor profile
type Profile struct {
	Name string
	ProfileHeader
	Rules
	FromSource  map[string]FromSourceConfig
	NativeRules []string
}

// Init initialises elements Profike Structure
func (p *Profile) Init() {
	p.ProfileHeader.Init()
	p.Rules.Init()
	p.FromSource = make(map[string]FromSourceConfig)
}

// Inspired from https://github.com/genuinetools/bane/blob/master/apparmor/template.go

// BaseTemplate for AppArmor profiles
const BaseTemplate = `
## == Managed by KubeArmor == ##
#include <tunables/global>
{{- $ctx := .}}
{{- $regex := ".*?(\\[|\\*|\\+|\\?|\\$|\\|)+.*"}}
{{- $fromSourceList := list }}
{{- range $source, $data := .FromSource }}
{{- $fromSourceList = append $fromSourceList $source}}
{{- end }}

## == Dispatcher profile START == ##
profile {{.Name}} flags=(attach_disconnected,mediate_deleted) {
	{{- template "pre-section" . }}
  {{template "file-section" . }}
	## == DISPATCHER START == ##
  {{- range $source, $value:= $.FromSource}}
				{{$source}} px -> {{$v := $.Name | split "."}}{{$v._0}}_{{ regexReplaceAllLiteral "[^a-z A-Z 0-9]" $source "" }},
  {{- end}}
	{{- range $value, $data := .ProcessPaths}}
		{{- $suffix := ""}}
    {{- $ext := "" }}
		{{- if and $data.Dir $data.Recursive}}
			{{- $suffix = "{,**}"}}
      {{- $ext = "-**" }}
		{{- else if $data.Dir}}
			{{- $suffix = "{,*}"}}
      {{- $ext = "-*" }}
		{{- end}}
		{{- if $data.Deny}}
			{{- if $data.OwnerOnly}}
				owner {{$value}}{{$suffix}} ix,
				deny other {{$value}}{{$suffix}} x,
			{{- else}}
				deny {{$value}}{{$suffix}} x,
			{{- end}}
		{{- end}}

		{{- if $data.Allow}}
			{{- if and (eq $suffix "") (not (regexMatch $regex $value)) }}
				{{- if $data.OwnerOnly}}
					owner {{$value}} ix,
				{{- else}}
					{{$value}} ix,
				{{- end}}
      {{- else if not (regexMatch $regex $value)}}
      	{{$value}}{{$suffix}} ix,
      {{- else}}
      	## {{$value}} px -> {{$.Name}}-{{$value}}
			{{- end}}
		{{- end}}
	{{- end}}
	## == DISPATCHER END == ##
  {{template "network-section" .}}
  {{template "capabilities-section" .}}
  {{template "native-policy" . }}
  
	## == POST START == ##
	/lib/x86_64-linux-gnu/{*,**} rm,

	{{ if not .Privileged }}
	deny @{PROC}/{*,**^[0-9*],sys/kernel/shm*} wkx,
	deny @{PROC}/sysrq-trigger rwklx,
	deny @{PROC}/mem rwklx,
	deny @{PROC}/kmem rwklx,
	deny @{PROC}/kcore rwklx,

	deny mount,
	
	deny /sys/[^f]*/** wklx,
	deny /sys/f[^s]*/** wklx,
	deny /sys/fs/[^c]*/** wklx,
	deny /sys/fs/c[^g]*/** wklx,
	deny /sys/fs/cg[^r]*/** wklx,
	deny /sys/firmware/efi/efivars/** rwklx,
	deny /sys/kernel/security/** rwklx,
	{{end}}

	## == POST END == ##
}
## == Dispatcher profile END == ##

## == FromSource per binary profiles START == ##
{{- range $source, $value := $.FromSource}}
profile {{$v := $.Name | split "."}}{{$v._0}}_{{ regexReplaceAllLiteral "[^a-z A-Z 0-9]" $source "" }} {
	{{$source}} rix,
	{{template "pre-section" $value }}
  {{template "file-section" $value}}
 	## == DISPATCHER START == ##
	{{- range $value, $data := .ProcessPaths}}
		{{- $suffix := ""}}
		{{- if and $data.Dir $data.Recursive}}
			{{- $suffix = "{,**}"}}
		{{- else if $data.Dir}}
			{{- $suffix = "{,*}"}}
		{{- end}}
		{{- if $data.Deny}}
			{{- if $data.OwnerOnly}}
				owner {{$value}}{{$suffix}} ix,
				deny other {{$value}}{{$suffix}} x,
			{{- else}}
				deny {{$value}}{{$suffix}} x,
			{{- end}}
		{{- end}}

		{{- if $data.Allow}}
			{{- if eq $suffix "" }}
      	{{- if has $value $fromSourceList }}
        	{{- if $data.OwnerOnly}}
						owner {{$value}} px -> {{$.Name}}-{{$value}},
					{{- else}}
						{{$value}} px -> {{$.Name}}-{{$value}},
					{{- end}}
        {{- else}}
        	{{- if $data.OwnerOnly}}
						owner {{$value}} cx,
					{{- else}}
						{{$value}} cx,
            profile {{$value}} {
            {{$value}} rix,
            {{template "pre-section" $ctx}}
            {{template "file-section" $ctx}}
            {{template "network-section" $ctx}}
  					{{template "capabilities-section" $ctx}}
            {{template "post-section" }}
            }
					{{- end}}
        {{- end}}	
			{{- end}}
		{{- end}}
	{{- end}}
	## == DISPATCHER END == ##
  {{template "network-section" .}}
  {{template "capabilities-section" .}}
  {{template "post-section" }}
}
{{- end}}
## == FromSource per binary profiles END == ##

## == Templates section START == ##

{{define "pre-section"}}
	## == PRE START == ##
	#include <abstractions/base>
	{{ if .Privileged }}
	## == For privileged workloads == ##
	umount,
	mount,
	signal,
	unix,
	ptrace,
	dbus,
	{{end}}
	{{ if .File}}file,{{end}}
	{{ if .Network}}network,{{end}}
	{{ if .Capabilities}}capability,{{end}}
	## == PRE END == ##
{{- end}}

{{define "network-section"}}
  ## == Network START == ##
	{{- range $value, $data := .NetworkRules}}
    {{- if $data.Deny}}
	  {{- if eq $value "all" }}
	  deny network,
	  {{- else }}
      deny network {{$value}},
	  {{- end}}
    {{- end}}
    {{- if $data.Allow}}
      network {{$value}},
    {{- end}}
  {{- end}}
  ## == Network END == ##
{{- end}}

{{define "capabilities-section"}}
  ## == Capabilities START == ##
  {{- range $value, $data := .CapabilitiesRules}}
    {{- if $data.Deny}}
      deny capability
    {{$value}},
    {{- end}}
    {{- if $data.Allow}}
      capability {{$value}},
    {{- end}}
  {{- end}}
  ## == Capabilities END == ##
{{- end}}

{{ define "file-section"}}
	## == File/Dir START == ##
  {{- range $value, $data := .FilePaths}}
  	{{- $suffix := ""}}
  	{{- if and $data.Dir $data.Recursive}}
      {{- $suffix = "{,**}"}}
    {{- else if $data.Dir}}
      {{- $suffix = "{,*}"}}
    {{- end}}
    {{- if $data.Deny}}
      {{- if and $data.ReadOnly $data.OwnerOnly}}
        deny owner {{$value}}{{$suffix}} klw,
        deny other {{$value}}{{$suffix}} klmrw,
      {{- else if $data.OwnerOnly}}
        owner {{$value}}{{$suffix}} klmrw,
        deny other {{$value}}{{$suffix}} klmrw,
      {{- else if $data.ReadOnly}}
        deny {{$value}}{{$suffix}} klw,
      {{- else}}
        deny {{$value}}{{$suffix}} klmrw,
      {{- end}}
    {{- end}}
    {{- if $data.Allow}}
      {{- if and $data.ReadOnly $data.OwnerOnly}}
        owner {{$value}}{{$suffix}} klr,
      {{- else if $data.OwnerOnly}}
        owner {{$value}}{{$suffix}} klmrw,
      {{- else if $data.ReadOnly}}
        {{$value}}{{$suffix}} klr,
      {{- else}}
        {{$value}}{{$suffix}} klmrw,
      {{- end}}
    {{- end}}
	{{- end}}
	## == File/Dir END == ##
{{- end}}

{{ define "post-section"}}
	## == POST START == ##
	/lib/x86_64-linux-gnu/{*,**} rm,

	## == POST END == ##
{{- end -}}

{{ define "native-policy"}}
	## == Native Policy START == ##
{{ if gt (len .NativeRules) 0 }}	## == NATIVE POLICY START == ##
	{{- range $value := .NativeRules}}
  	{{$value}}
	{{end}}
{{end}}
	## == Native Policy END == ##
{{ end}}
`
