// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package core

import (
	"reflect"
	"testing"
)

// TestParseAppArmorAnnotations verifies that malformed AppArmor annotations
// (a bare prefix key with no container suffix, or a value without a
// "localhost/<profile>" separator) are skipped with a warning instead of
// causing an index-out-of-range panic.
func TestParseAppArmorAnnotations(t *testing.T) {
	tests := []struct {
		name         string
		annotations  map[string]string
		wantProfiles map[string]string
		wantWarnings int
	}{
		{
			name: "well-formed unconfined annotation",
			annotations: map[string]string{
				"container.apparmor.security.beta.kubernetes.io/nginx": "unconfined",
			},
			wantProfiles: map[string]string{"nginx": "unconfined"},
			wantWarnings: 0,
		},
		{
			name: "well-formed localhost profile annotation",
			annotations: map[string]string{
				"container.apparmor.security.beta.kubernetes.io/nginx": "localhost/my-profile",
			},
			wantProfiles: map[string]string{"nginx": "my-profile"},
			wantWarnings: 0,
		},
		{
			name: "malformed key without container suffix",
			annotations: map[string]string{
				"container.apparmor.security.beta.kubernetes.io": "unconfined",
			},
			wantProfiles: map[string]string{},
			wantWarnings: 1,
		},
		{
			name: "malformed value without separator",
			annotations: map[string]string{
				"container.apparmor.security.beta.kubernetes.io/nginx": "not-a-valid-profile-string",
			},
			wantProfiles: map[string]string{},
			wantWarnings: 1,
		},
		{
			name: "unrelated annotations are ignored",
			annotations: map[string]string{
				"some-other-annotation": "value",
			},
			wantProfiles: map[string]string{},
			wantWarnings: 0,
		},
		{
			name:         "nil annotations",
			annotations:  nil,
			wantProfiles: map[string]string{},
			wantWarnings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotProfiles, gotWarnings := parseAppArmorAnnotations(tt.annotations)
			if !reflect.DeepEqual(gotProfiles, tt.wantProfiles) {
				t.Errorf("parseAppArmorAnnotations() profiles = %v, want %v", gotProfiles, tt.wantProfiles)
			}
			if len(gotWarnings) != tt.wantWarnings {
				t.Errorf("parseAppArmorAnnotations() warnings = %v, want %d warnings", gotWarnings, tt.wantWarnings)
			}
		})
	}
}
