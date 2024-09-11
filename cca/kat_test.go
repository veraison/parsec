// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package cca

import (
	"encoding/hex"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testGoodKAT = `
		d90259a20a56612070736575646f2d72616e646f6d20737472696e6708a1
		01a60102032620012158206b17d1f2e12c4247f8bce6e563a440f277037d
		812deb33a0f4a13945d898c2962258204fe342e2fe1a7f9b8ee7eb4a7c0f
		9e162bce33576b315ececbb6406837bf51f5234101
	`
	testBadNonceKAT = `
		d90259a20a416108a101a60102032620012158206b17d1f2e12c4247f8bc
		e6e563a440f277037d812deb33a0f4a13945d898c2962258204fe342e2fe
		1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5234101
	`
	testNoTagKAT = `
		a20a56612070736575646f2d72616e646f6d20737472696e6708a101a601
		02032620012158206b17d1f2e12c4247f8bce6e563a440f277037d812deb
		33a0f4a13945d898c2962258204fe342e2fe1a7f9b8ee7eb4a7c0f9e162b
		ce33576b315ececbb6406837bf51f5234101
	`
	testNoCnfKAT = `
		d90259a10a56612070736575646f2d72616e646f6d20737472696e67
	`
	testNoNonceKAT = `
		d90259a108a101a60102032620012158206b17d1f2e12c4247f8bce6e563
		a440f277037d812deb33a0f4a13945d898c2962258204fe342e2fe1a7f9b
		8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5234101
	`
	testBadCnfKAT = `
		d90259a20a56612070736575646f2d72616e646f6d20737472696e6708a1
		01a60102032620042158206b17d1f2e12c4247f8bce6e563a440f277037d
		812deb33a0f4a13945d898c2962258204fe342e2fe1a7f9b8ee7eb4a7c0f
		9e162bce33576b315ececbb6406837bf51f5234101
	`
)

func mustHexDecode(t *testing.T, s string) []byte {
	emptiness := regexp.MustCompile("[ \t\n]")

	s = emptiness.ReplaceAllString(s, "")

	data, err := hex.DecodeString(s)
	if t != nil {
		require.NoError(t, err)
	} else if err != nil {
		panic(err)
	}
	return data
}

func TestKAT_FromCBOR_ok(t *testing.T) {
	tv := mustHexDecode(t, testGoodKAT)

	var actual KAT
	err := actual.FromCBOR(tv)
	assert.NoError(t, err)
}

func TestKAT_FromCBOR_fail_bad_nonce(t *testing.T) {
	tv := mustHexDecode(t, testBadNonceKAT)

	var actual KAT
	err := actual.FromCBOR(tv)

	expectedErr := `KAT validation failed: nonce validation failed: found invalid nonce at index 0: `
	expectedErr += `a nonce must be between 8 and 64 bytes long; found 1`

	assert.EqualError(t, err, expectedErr)
}

func TestKAT_FromCBOR_fail_no_uccs_tag(t *testing.T) {
	tv := mustHexDecode(t, testNoTagKAT)

	var actual KAT
	err := actual.FromCBOR(tv)

	expectedErr := `KAT decoding failed: cbor: cannot unmarshal map into Go value of type cca.KAT (expect CBOR tag value)`

	assert.EqualError(t, err, expectedErr)
}

func TestKAT_FromCBOR_fail_no_cnf_claim(t *testing.T) {
	tv := mustHexDecode(t, testNoCnfKAT)

	var actual KAT
	err := actual.FromCBOR(tv)

	expectedErr := `KAT validation failed: cnf claim missing`

	assert.EqualError(t, err, expectedErr)
}

func TestKAT_FromCBOR_fail_no_nonce_claim(t *testing.T) {
	tv := mustHexDecode(t, testNoNonceKAT)

	var actual KAT
	err := actual.FromCBOR(tv)

	expectedErr := `KAT validation failed: nonce claim missing`

	assert.EqualError(t, err, expectedErr)
}

func TestKAT_FromCBOR_fail_bad_cnf(t *testing.T) {
	tv := mustHexDecode(t, testBadCnfKAT)

	var actual KAT
	err := actual.FromCBOR(tv)

	expectedErr := `KAT decoding failed: invalid key`

	assert.ErrorContains(t, err, expectedErr)
}
