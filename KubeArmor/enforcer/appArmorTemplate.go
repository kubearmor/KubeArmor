// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package enforcer

// ProfileHeader contain sAppArmor Profile/SubProfile header config
type ProfileHeader struct {
	File, Network, Capabilities bool
}

// Init sets the presence of Entity headers to true by default
func (h *ProfileHeader) Init() {
	h.File = true
	h.Network = true
	h.Capabilities = true
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

profile {{.Name}} flags=(attach_disconnected,mediate_deleted) {

	## == PRE START == ##

	#include <abstractions/base>

{{if .File}}	file,
{{end}}{{if .Network}}	network,
{{end}}{{if .Capabilities}}	capability,
{{end}}
	## == PRE END == ##

	## == POLICY START == ##
{{range $value, $data := .FilePaths}}{{$suffix := ""}}{{if and $data.Dir $data.Recursive}}{{$suffix = "**"}}{{else if $data.Dir}}{{$suffix = "*"}}{{end}}{{if $data.Deny}}{{if and $data.ReadOnly $data.OwnerOnly}}
	deny owner {{$value}}{{$suffix}} w,
	deny other {{$value}}{{$suffix}} rw,
{{else if $data.OwnerOnly}}	owner {{$value}}{{$suffix}} rw,
	deny other {{$value}}{{$suffix}} rw,
{{else if $data.ReadOnly}}	deny {{$value}}{{$suffix}} w,
{{else}}	deny {{$value}}{{$suffix}} rw,{{end}}
{{end}}{{if $data.Allow}}{{if and $data.ReadOnly $data.OwnerOnly}}	owner {{$value}}{{$suffix}} r,
{{else if $data.OwnerOnly}}	owner {{$value}}{{$suffix}} rw,
{{else if $data.ReadOnly}}	{{$value}}{{$suffix}} r,
{{else}}	{{$value}}{{$suffix}} rw,
{{end}}{{end}}{{end}}
{{range $value, $data := .ProcessPaths}}{{$suffix := ""}}{{if and $data.Dir $data.Recursive}}{{$suffix = "**"}}{{else if $data.Dir}}{{$suffix = "*"}}{{end}}{{if $data.Deny}}{{if $data.OwnerOnly}}
	owner {{$value}}{{$suffix}} ix,
	deny other {{$value}}{{$suffix}} x,{{else}}
	deny {{$value}}{{$suffix}} x,{{end}}{{end}}{{if $data.Allow}}{{if $data.OwnerOnly}}
	owner {{$value}}{{$suffix}} ix,{{else}}	{{$value}}{{$suffix}} ix,
{{end}}{{end}}{{end}}
{{range $value, $data := .NetworkRules}}{{if $data.Deny}}	deny network {{$value}},
{{end}}{{if $data.Allow}}	network {{$value}},
{{end}}{{end}}
{{range $value, $data := .CapabilitiesRules}}{{if $data.Deny}}	deny capability {{$value}},
{{end}}{{if $data.Allow}}	capability {{$value}},
{{end}}{{end}}
{{ range $source, $value := $.FromSource }}{{if $value.Fusion}}
	{{$source}} cix,{{else}}
	{{$source}} cx,{{end}}
	profile {{$source}} {

		{{$source}} rix,
		## == PRE START == ##

		#include <abstractions/base>
	
	{{if .File}}	file,
	{{end}}{{if .Network}}	network,
	{{end}}{{if .Capabilities}}	capability,
	{{end}}
		## == PRE END == ##
	
		## == POLICY START == ##
	{{range $value, $data := .FilePaths}}{{$suffix := ""}}{{if and $data.Dir $data.Recursive}}{{$suffix = "**"}}{{else if $data.Dir}}{{$suffix = "*"}}{{end}}{{if $data.Deny}}{{if and $data.ReadOnly $data.OwnerOnly}}
		deny owner {{$value}}{{$suffix}} w,
		deny other {{$value}}{{$suffix}} rw,
	{{else if $data.OwnerOnly}}	owner {{$value}}{{$suffix}} rw,
		deny other {{$value}}{{$suffix}} rw,
	{{else if $data.ReadOnly}}	deny {{$value}}{{$suffix}} w,
	{{else}}	deny {{$value}}{{$suffix}} rw,{{end}}
	{{end}}{{if $data.Allow}}{{if and $data.ReadOnly $data.OwnerOnly}}	owner {{$value}}{{$suffix}} r,
	{{else if $data.OwnerOnly}}	owner {{$value}}{{$suffix}} rw,
	{{else if $data.ReadOnly}}	{{$value}}{{$suffix}} r,
	{{else}}	{{$value}}{{$suffix}} rw,
	{{end}}{{end}}{{end}}
	{{range $value, $data := .ProcessPaths}}{{$suffix := ""}}{{if and $data.Dir $data.Recursive}}{{$suffix = "**"}}{{else if $data.Dir}}{{$suffix = "*"}}{{end}}{{if $data.Deny}}{{if $data.OwnerOnly}}
		owner {{$value}}{{$suffix}} ix,
		deny other {{$value}}{{$suffix}} x,{{else}}
		deny {{$value}}{{$suffix}} x,{{end}}{{end}}{{if $data.Allow}}{{if $data.OwnerOnly}}
		owner {{$value}}{{$suffix}} ix,{{else}}	{{$value}}{{$suffix}} ix,
	{{end}}{{end}}{{end}}
	{{range $value, $data := .NetworkRules}}{{if $data.Deny}}	deny network {{$value}},
	{{end}}{{if $data.Allow}}	network {{$value}},
	{{end}}{{end}}
	{{range $value, $data := .CapabilitiesRules}}{{if $data.Deny}}	deny capability {{$value}},
	{{end}}{{if $data.Allow}}	capability {{$value}},
	{{end}}{{end}}
		## == POLICY END == ##
	
		## == POST START == ##
	
		/lib/x86_64-linux-gnu/{*,**} rm,
		
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
	
		## == POST END == ##

	}
{{end}}
	## == POLICY END == ##
{{ if gt (len .NativeRules) 0 }}	## == NATIVE POLICY START == ##
{{range $value := .NativeRules}}	{{$value}}
{{end}}	## == NATIVE POLICY END == ##
{{end}}
	## == POST START == ##

	/lib/x86_64-linux-gnu/{*,**} rm,
	
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

	## == POST END == ##

}
`
