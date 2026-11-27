// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGeneratePki(t *testing.T) {
	caPEM, caKeyPEM, crtPEM, crtKeyPEM, err := GeneratePki("test-ns", "test-svc")
	assert.NoError(t, err)
	assert.NotNil(t, caPEM)
	assert.NotNil(t, caKeyPEM)
	assert.NotNil(t, crtPEM)
	assert.NotNil(t, crtKeyPEM)

	assert.NotEmpty(t, caPEM.Bytes())
	assert.NotEmpty(t, caKeyPEM.Bytes())
	assert.NotEmpty(t, crtPEM.Bytes())
	assert.NotEmpty(t, crtKeyPEM.Bytes())
}

func TestGeneratePkiWithCA(t *testing.T) {
	caPEM, caKeyPEM, _, _, err := GeneratePki("test-ns", "test-svc")
	assert.NoError(t, err)

	caCert, crtPEM, crtKeyPEM, err := GeneratePkiWithCA("test-ns", "test-svc", caPEM.Bytes(), caKeyPEM.Bytes())
	assert.NoError(t, err)
	assert.NotNil(t, caCert)
	assert.NotNil(t, crtPEM)
	assert.NotNil(t, crtKeyPEM)

	assert.Equal(t, caPEM.Bytes(), caCert.Bytes())
	assert.NotEmpty(t, crtPEM.Bytes())
	assert.NotEmpty(t, crtKeyPEM.Bytes())
}

func TestGeneratePkiWithCAInvalid(t *testing.T) {
	_, _, _, err := GeneratePkiWithCA("test-ns", "test-svc", []byte("invalid cert"), []byte("invalid key"))
	assert.Error(t, err)

	caPEM, _, _, _, err := GeneratePki("test-ns", "test-svc")
	assert.NoError(t, err)

	_, _, _, err = GeneratePkiWithCA("test-ns", "test-svc", caPEM.Bytes(), []byte("invalid key"))
	assert.Error(t, err)
}
