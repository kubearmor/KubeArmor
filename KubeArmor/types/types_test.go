// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/json"
	"testing"
)

func TestEndPointMarshalJSONIncludesCorrectAndLegacyPrivilegedContainersKeys(t *testing.T) {
	endpoint := EndPoint{
		PrivilegedContainers: map[string]struct{}{
			"demo": {},
		},
	}

	data, err := json.Marshal(endpoint)
	if err != nil {
		t.Fatalf("marshal endpoint: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal marshaled endpoint: %v", err)
	}

	for _, key := range []string{"privilegedContainers", "privilegdContainers"} {
		value, ok := decoded[key]
		if !ok {
			t.Fatalf("expected JSON key %q in marshaled endpoint", key)
		}
		containers, ok := value.(map[string]any)
		if !ok {
			t.Fatalf("expected JSON key %q to contain an object", key)
		}
		if _, ok := containers["demo"]; !ok {
			t.Fatalf("expected container name under JSON key %q", key)
		}
	}
}

func TestEndPointUnmarshalJSONAcceptsLegacyPrivilegedContainersKey(t *testing.T) {
	var endpoint EndPoint

	err := json.Unmarshal([]byte(`{"privilegdContainers":{"legacy":{}}}`), &endpoint)
	if err != nil {
		t.Fatalf("unmarshal endpoint with legacy key: %v", err)
	}

	if _, ok := endpoint.PrivilegedContainers["legacy"]; !ok {
		t.Fatalf("expected legacy privileged container key to populate field")
	}
}

func TestEndPointUnmarshalJSONPrefersCorrectPrivilegedContainersKey(t *testing.T) {
	var endpoint EndPoint

	err := json.Unmarshal([]byte(`{
		"privilegedContainers":{"correct":{}},
		"privilegdContainers":{"legacy":{}}
	}`), &endpoint)
	if err != nil {
		t.Fatalf("unmarshal endpoint with both keys: %v", err)
	}

	if _, ok := endpoint.PrivilegedContainers["correct"]; !ok {
		t.Fatalf("expected corrected key to populate field")
	}
	if _, ok := endpoint.PrivilegedContainers["legacy"]; ok {
		t.Fatalf("expected corrected key to take precedence over legacy key")
	}
}
