// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package bpflsm

import (
	"testing"
)

func TestRuleMapEntries(t *testing.T) {
	var r RuleList
	r.Init()

	// one recursive directory rule: the dir itself, dir/, and one hint per parent ("/", "/var/")
	dirtoMap(FILE, "/var/mail/", "", r.FileRuleList, [2]uint16{})
	if got := ruleMapEntries(r); got != 4 {
		t.Fatalf("dir rule: got %d entries, want 4", got)
	}

	// a process rule on a key that a file rule already uses shares the entry
	var k InnerKey
	copy(k.Path[:], "/var/mail")
	r.ProcessRuleList[k] = [2]uint16{EXEC}
	if got := ruleMapEntries(r); got != 4 {
		t.Fatalf("shared key: got %d entries, want 4", got)
	}

	// whitelist posture keys take one entry each
	r.FileWhiteListPosture = true
	r.ProcWhiteListPosture = true
	if got := ruleMapEntries(r); got != 6 {
		t.Fatalf("posture keys: got %d entries, want 6", got)
	}
}
