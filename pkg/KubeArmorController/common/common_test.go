// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package common

import "testing"

func Test_appArmorProfileSupportMinVersion(t *testing.T) {
	tests := []struct {
		name           string
		clusterVersion string
		want           bool
	}{
		{
			name:           "no version should return false",
			clusterVersion: "",
			want:           false,
		},
		{
			name:           "version greater than min should return true",
			clusterVersion: "1.31.0",
			want:           true,
		},
		{
			name:           "version equal to min should return true",
			clusterVersion: "1.30.0",
			want:           true,
		},
		{
			name:           "version less than min should return false",
			clusterVersion: "1.29.0",
			want:           false,
		},
		{
			name:           "invalid version format should return false",
			clusterVersion: "invalid",
			want:           false,
		},
		{
			name:           "version with vendor suffix greater than min should return true",
			clusterVersion: "v1.32.1+k0s",
			want:           true,
		},
		{
			name:           "version with vendor suffix less than min should return true",
			clusterVersion: "v1.29.1+k0s",
			want:           false,
		},
		{
			name:           "version without patch equal to min should return true",
			clusterVersion: "1.30",
			want:           true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isAppArmorProfileSupportMinVersion(tt.clusterVersion); got != tt.want {
				t.Errorf("isAppArmorProfileSupportMinVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}
