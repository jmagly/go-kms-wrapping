// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test_GetOpts provides unit tests for GetOpts and all the options
func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithKeyId", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withKeyId = ""
		assert.Equal(opts, testOpts)

		const with = "testKeyId"
		opts, err = getOpts(WithKeyId(with))
		require.NoError(err)
		testOpts.withKeyId = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithSlot", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withSlot = ""
		assert.Equal(opts, testOpts)

		const with = "1024"
		opts, err = getOpts(WithSlot(with))
		require.NoError(err)
		testOpts.withSlot = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithPin", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withPin = ""
		assert.Equal(opts, testOpts)

		const with = "000000"
		opts, err = getOpts(WithPin(with))
		require.NoError(err)
		testOpts.withPin = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithLib", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withLib = ""
		assert.Equal(opts, testOpts)

		const with = "/usr/lib/pkcs11.so"
		opts, err = getOpts(WithLib(with))
		require.NoError(err)
		testOpts.withLib = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithTokenLabel", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withTokenLabel = ""
		assert.Equal(opts, testOpts)

		const with = "labelTest"
		opts, err = getOpts(WithTokenLabel(with))
		require.NoError(err)
		testOpts.withTokenLabel = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithMechanism", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		// test default of 0
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withMechanism = ""
		assert.Equal(opts, testOpts)

		const with = "CKM_AES_GCM"
		opts, err = getOpts(WithMechanism(with))
		require.NoError(err)
		testOpts.withMechanism = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithGenerateKey", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		opts, err := getOpts()
		require.NoError(err)
		testOpts, err := getOpts()
		require.NoError(err)
		testOpts.withGenerateKey = ""
		assert.Equal(opts, testOpts)

		const with = "true"
		opts, err = getOpts(WithGenerateKey(with))
		require.NoError(err)
		testOpts.withGenerateKey = with
		assert.Equal(opts, testOpts)
	})
	t.Run("WithGenerateKeyConfigMap", func(t *testing.T) {
		require := require.New(t)
		opts, err := getOpts(wrapping.WithConfigMap(map[string]string{
			"generate_key": "true",
			"lib":          "/usr/lib/pkcs11.so",
			"slot":         "0",
			"pin":          "1234",
			"key_label":    "test",
		}))
		require.NoError(err)
		require.Equal("true", opts.withGenerateKey)
	})
}
