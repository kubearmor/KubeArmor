// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package base

import (
	"testing"

	"github.com/kubearmor/KubeArmor/KubeArmor/buildinfo"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// ── AddPolicyLogInfo ──────────────────────────────────────────────────────────

func TestAddPolicyLogInfo(t *testing.T) {
	tests := []struct {
		name      string
		ckv       ContainerVal
		wantName  string
		wantTags  string
		wantATags []string
		wantSev   string
		wantMsg   string
		wantType  string
	}{
		{
			name:      "empty_policy",
			ckv:       ContainerVal{},
			wantName:  "",
			wantTags:  "",
			wantATags: nil,
			wantSev:   "",
			wantMsg:   "",
			wantType:  "MatchedPolicy",
		},
		{
			name: "policy_name_only",
			ckv: ContainerVal{
				Policy: tp.MatchPolicy{PolicyName: "test-policy"},
			},
			wantName:  "test-policy",
			wantTags:  "",
			wantATags: nil,
			wantSev:   "",
			wantMsg:   "",
			wantType:  "MatchedPolicy",
		},
		{
			name: "single_tag",
			ckv: ContainerVal{
				Policy: tp.MatchPolicy{
					PolicyName: "p1",
					Tags:       []string{"cis"},
				},
			},
			wantName:  "p1",
			wantTags:  "cis",
			wantATags: []string{"cis"},
			wantSev:   "",
			wantMsg:   "",
			wantType:  "MatchedPolicy",
		},
		{
			name: "multiple_tags",
			ckv: ContainerVal{
				Policy: tp.MatchPolicy{
					PolicyName: "p2",
					Tags:       []string{"cis", "nist", "pci"},
				},
			},
			wantName:  "p2",
			wantTags:  "cis,nist,pci",
			wantATags: []string{"cis", "nist", "pci"},
			wantSev:   "",
			wantMsg:   "",
			wantType:  "MatchedPolicy",
		},
		{
			name: "severity_and_message",
			ckv: ContainerVal{
				Policy: tp.MatchPolicy{
					PolicyName: "p3",
					Severity:   "5",
					Message:    "suspicious exec detected",
				},
			},
			wantName:  "p3",
			wantTags:  "",
			wantATags: nil,
			wantSev:   "5",
			wantMsg:   "suspicious exec detected",
			wantType:  "MatchedPolicy",
		},
		{
			name: "all_fields_set",
			ckv: ContainerVal{
				NsKey: NsKey{PidNS: 100, MntNS: 200},
				Policy: tp.MatchPolicy{
					PolicyName: "full-policy",
					Severity:   "3",
					Message:    "alert",
					Tags:       []string{"cis", "nist"},
				},
			},
			wantName:  "full-policy",
			wantTags:  "cis,nist",
			wantATags: []string{"cis", "nist"},
			wantSev:   "3",
			wantMsg:   "alert",
			wantType:  "MatchedPolicy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := &tp.Log{}
			AddPolicyLogInfo(log, &tt.ckv)

			if log.PolicyName != tt.wantName {
				t.Errorf("PolicyName = %q, want %q", log.PolicyName, tt.wantName)
			}
			if log.Tags != tt.wantTags {
				t.Errorf("Tags = %q, want %q", log.Tags, tt.wantTags)
			}
			if len(log.ATags) != len(tt.wantATags) {
				t.Errorf("ATags length = %d, want %d", len(log.ATags), len(tt.wantATags))
			} else {
				for i := range tt.wantATags {
					if log.ATags[i] != tt.wantATags[i] {
						t.Errorf("ATags[%d] = %q, want %q", i, log.ATags[i], tt.wantATags[i])
					}
				}
			}
			if log.Severity != tt.wantSev {
				t.Errorf("Severity = %q, want %q", log.Severity, tt.wantSev)
			}
			if log.Message != tt.wantMsg {
				t.Errorf("Message = %q, want %q", log.Message, tt.wantMsg)
			}
			if log.Type != tt.wantType {
				t.Errorf("Type = %q, want %q", log.Type, tt.wantType)
			}
			// KubeArmorVersion mirrors buildinfo.GitSummary at call time.
			// In unit tests, GitSummary is "" (no build-time injection).
			if log.KubeArmorVersion != buildinfo.GitSummary {
				t.Errorf("KubeArmorVersion = %q, want %q (buildinfo.GitSummary)", log.KubeArmorVersion, buildinfo.GitSummary)
			}
		})
	}
}

// ── UpdateMatchPolicy ─────────────────────────────────────────────────────────

func TestUpdateMatchPolicy(t *testing.T) {
	tests := []struct {
		name     string
		metadata map[string]string
		severity int
		message  string
		tags     []string
		wantName string
		wantSev  string
		wantMsg  string
		wantTags []string
	}{
		{
			name:     "zero_value_policy",
			metadata: map[string]string{},
			severity: 0,
			message:  "",
			tags:     nil,
			wantName: "",
			wantSev:  "0",
			wantMsg:  "",
			wantTags: nil,
		},
		{
			name:     "full_policy",
			metadata: map[string]string{"policyName": "block-exec"},
			severity: 5,
			message:  "blocked execution",
			tags:     []string{"cis", "nist"},
			wantName: "block-exec",
			wantSev:  "5",
			wantMsg:  "blocked execution",
			wantTags: []string{"cis", "nist"},
		},
		{
			name:     "missing_policyname_key",
			metadata: map[string]string{"other": "value"},
			severity: 3,
			message:  "msg",
			tags:     []string{"t1"},
			wantName: "",
			wantSev:  "3",
			wantMsg:  "msg",
			wantTags: []string{"t1"},
		},
		{
			name:     "high_severity",
			metadata: map[string]string{"policyName": "critical-policy"},
			severity: 10,
			message:  "critical",
			tags:     []string{"critical"},
			wantName: "critical-policy",
			wantSev:  "10",
			wantMsg:  "critical",
			wantTags: []string{"critical"},
		},
		{
			name:     "single_tag",
			metadata: map[string]string{"policyName": "p"},
			severity: 1,
			message:  "",
			tags:     []string{"pci"},
			wantName: "p",
			wantSev:  "1",
			wantMsg:  "",
			wantTags: []string{"pci"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ckv := &ContainerVal{}
			secPolicy := &tp.SecurityPolicy{
				Metadata: tt.metadata,
				Spec: tp.SecuritySpec{
					Severity: tt.severity,
					Message:  tt.message,
					Tags:     tt.tags,
				},
			}

			UpdateMatchPolicy(ckv, secPolicy)

			if ckv.Policy.PolicyName != tt.wantName {
				t.Errorf("PolicyName = %q, want %q", ckv.Policy.PolicyName, tt.wantName)
			}
			if ckv.Policy.Severity != tt.wantSev {
				t.Errorf("Severity = %q, want %q", ckv.Policy.Severity, tt.wantSev)
			}
			if ckv.Policy.Message != tt.wantMsg {
				t.Errorf("Message = %q, want %q", ckv.Policy.Message, tt.wantMsg)
			}
			if len(ckv.Policy.Tags) != len(tt.wantTags) {
				t.Errorf("Tags length = %d, want %d", len(ckv.Policy.Tags), len(tt.wantTags))
			} else {
				for i := range tt.wantTags {
					if ckv.Policy.Tags[i] != tt.wantTags[i] {
						t.Errorf("Tags[%d] = %q, want %q", i, ckv.Policy.Tags[i], tt.wantTags[i])
					}
				}
			}
		})
	}
}

// ── Constants (basePreset.go) ─────────────────────────────────────────────────

func TestPresetConstants(t *testing.T) {
	if PRESET_ENFORCER != "PRESET-" {
		t.Errorf("PRESET_ENFORCER = %q, want %q", PRESET_ENFORCER, "PRESET-")
	}
	if Audit != 1 {
		t.Errorf("Audit = %d, want 1", Audit)
	}
	if Block != 2 {
		t.Errorf("Block = %d, want 2", Block)
	}
}

// ── Struct construction (basePreset.go) ───────────────────────────────────────

func TestNsKeyConstruction(t *testing.T) {
	tests := []struct {
		name  string
		pidNS uint32
		mntNS uint32
	}{
		{"zero_values", 0, 0},
		{"typical_values", 4026531836, 4026531840},
		{"max_values", ^uint32(0), ^uint32(0)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := NsKey{PidNS: tt.pidNS, MntNS: tt.mntNS}
			if key.PidNS != tt.pidNS {
				t.Errorf("PidNS = %d, want %d", key.PidNS, tt.pidNS)
			}
			if key.MntNS != tt.mntNS {
				t.Errorf("MntNS = %d, want %d", key.MntNS, tt.mntNS)
			}
		})
	}
}
