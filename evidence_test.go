// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package parsectpm

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Evidence_FromCBOR_ok(t *testing.T) {
	tokenBytes, err := os.ReadFile("test/evidence.cbor")
	require.NoError(t, err)

	e := &Evidence{}
	err = e.FromCBOR(tokenBytes)
	require.NoError(t, err)
}

func Test_Evidence_FromCBOR_nok(t *testing.T) {
	tokenBytes, err := os.ReadFile("test/bad_evidence.cbor")
	require.NoError(t, err)
	expectedErr := "CBOR decoding of Parsec TPM attestation failed cbor: invalid additional information 28 for type byte string"
	e := &Evidence{}
	err = e.FromCBOR(tokenBytes)
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_ToCBOR_ok(t *testing.T) {
	var e Evidence
	err := e.SetTokens(
		mustBuildValidKAT(t),
		mustBuildValidPAT(t),
	)
	require.NoError(t, err)

	_, err = e.ToCBOR()
	require.NoError(t, err)
}

func TestEvidence_ToCBOR_InvalidPat(t *testing.T) {
	p := buildInValidPAT(t)
	k := mustBuildValidKAT(t)
	e := Evidence{Kat: k, Pat: p}
	expectedErr := "validation failed: validation of platform attestation token failed: missing key identifier"
	_, err := e.ToCBOR()
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_ToCBOR_InvalidKat(t *testing.T) {
	p := mustBuildValidPAT(t)
	k := buildInValidKAT(t)
	e := Evidence{Kat: k, Pat: p}
	expectedErr := "validation failed: validation of key attestation token failed: missing signature"
	_, err := e.ToCBOR()
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_ToCBOR_MissingPat(t *testing.T) {
	k := mustBuildValidKAT(t)
	e := Evidence{Kat: k}
	expectedErr := "validation failed: nil platform attestation token supplied"
	_, err := e.ToCBOR()
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_ToCBOR_MissingKat(t *testing.T) {
	p := mustBuildValidPAT(t)
	e := Evidence{Pat: p}
	expectedErr := "validation failed: nil key attestation token supplied"
	_, err := e.ToCBOR()
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_ToJSON_ok(t *testing.T) {
	e := Evidence{}
	err := e.SetTokens(
		mustBuildValidKAT(t),
		mustBuildValidPAT(t),
	)
	require.NoError(t, err)

	data, err := e.ToJSON()
	fmt.Printf("%s", data)
	require.NoError(t, err)
}

func TestEvidence_ToJSON_InvalidPat(t *testing.T) {
	p := buildInValidPAT(t)
	k := mustBuildValidKAT(t)
	e := Evidence{Kat: k, Pat: p}
	expectedErr := "validation failed: validation of platform attestation token failed: missing key identifier"
	_, err := e.ToJSON()
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_ToJSON_InvalidKat(t *testing.T) {
	p := mustBuildValidPAT(t)
	k := buildInValidKAT(t)
	e := Evidence{Kat: k, Pat: p}
	expectedErr := "validation failed: validation of key attestation token failed: missing signature"
	_, err := e.ToJSON()
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_ToJSON_missingPat(t *testing.T) {
	k := mustBuildValidKAT(t)
	e := Evidence{Kat: k}
	expectedErr := "validation failed: nil platform attestation token supplied"
	_, err := e.ToJSON()
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_ToJSON_missingKat(t *testing.T) {
	p := mustBuildValidPAT(t)
	e := Evidence{Pat: p}
	expectedErr := "validation failed: nil key attestation token supplied"
	_, err := e.ToJSON()
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_FromJSON_ok(t *testing.T) {
	tokenBytes, err := os.ReadFile("test/evidence.json")
	require.NoError(t, err)

	e := &Evidence{}
	err = e.FromJSON(tokenBytes)
	require.NoError(t, err)
}

func TestEvidence_FromJSON_missing_pat(t *testing.T) {
	tokenBytes, err := os.ReadFile("test/evidence_missing_pat.json")
	require.NoError(t, err)

	expectedErr := "validation failed: nil platform attestation token supplied"
	e := &Evidence{}
	err = e.FromJSON(tokenBytes)
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_FromJSON_missing_kat(t *testing.T) {
	tokenBytes, err := os.ReadFile("test/evidence_missing_kat.json")
	require.NoError(t, err)

	expectedErr := "validation failed: nil key attestation token supplied"
	e := &Evidence{}
	err = e.FromJSON(tokenBytes)
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_FromJSON_invalid_pat(t *testing.T) {
	tokenBytes, err := os.ReadFile("test/evidence_invalid_pat.json")
	require.NoError(t, err)

	expectedErr := "validation failed: validation of platform attestation token failed: missing key identifier"
	e := &Evidence{}
	err = e.FromJSON(tokenBytes)
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_FromJSON_invalid_kat(t *testing.T) {
	tokenBytes, err := os.ReadFile("test/evidence_invalid_kat.json")
	require.NoError(t, err)

	expectedErr := "validation failed: validation of key attestation token failed: validation failed: invalid certificate information: no digest information in certify info"
	e := &Evidence{}
	err = e.FromJSON(tokenBytes)
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_SetTokens_invalidPat(t *testing.T) {
	var e Evidence
	err := e.SetTokens(
		mustBuildValidKAT(t),
		buildInValidPAT(t),
	)
	expectedErr := "validation failed: validation of platform attestation token failed: missing key identifier"
	assert.EqualError(t, err, expectedErr)

}

func TestEvidence_SetTokens_invalidKat(t *testing.T) {
	var e Evidence
	err := e.SetTokens(
		buildInValidKAT(t),
		mustBuildValidPAT(t),
	)
	expectedErr := "validation failed: validation of key attestation token failed: missing signature"
	assert.EqualError(t, err, expectedErr)

}
func TestEvidence_SetTokens_missingKat(t *testing.T) {
	var e Evidence
	err := e.SetTokens(
		nil,
		mustBuildValidPAT(t),
	)
	expectedErr := "validation failed: nil key attestation token supplied"
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_Verify_missingBoth(t *testing.T) {
	var e Evidence
	key := generateTestECDSAKey(t)
	pk := key.Public().(*ecdsa.PublicKey)

	err := e.Verify(pk)
	expectedErr := "missing Parsec TPM key attestation token"
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_Verify_missingKat(t *testing.T) {
	e := &Evidence{Pat: mustBuildValidPAT(t)}
	key := generateTestECDSAKey(t)
	pk := key.Public().(*ecdsa.PublicKey)

	err := e.Verify(pk)
	expectedErr := "missing Parsec TPM key attestation token"
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_Verify_missingPat(t *testing.T) {
	e := &Evidence{Kat: mustBuildValidKAT(t)}
	key := generateTestECDSAKey(t)
	pk := key.Public().(*ecdsa.PublicKey)

	err := e.Verify(pk)
	expectedErr := "missing Parsec TPM platform attestation token"
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_Verify_ECKey_Failed(t *testing.T) {
	e := &Evidence{Kat: mustBuildValidKAT(t), Pat: mustBuildValidPAT(t)}
	key := generateTestECDSAKey(t)
	pk := key.Public().(*ecdsa.PublicKey)

	err := e.Verify(pk)
	expectedErr := "failed to verify signature on key attestation token: failed to verify signature: Verification failed"
	assert.EqualError(t, err, expectedErr)

}

func TestEvidence_Verify_RSAKey_Failed(t *testing.T) {
	e := &Evidence{Kat: mustBuildValidKAT(t), Pat: mustBuildValidPAT(t)}
	key := generateTestRSAKey(t)
	pk := key.Public().(*rsa.PublicKey)

	err := e.Verify(pk)
	expectedErr := "failed to verify signature on key attestation token: failed to verify signature: invalid public key type: *rsa.PublicKey"
	assert.EqualError(t, err, expectedErr)

}
func TestEvidence_Sign_Verify_ok(t *testing.T) {
	e := &Evidence{Kat: mustBuildValidKAT(t), Pat: mustBuildValidPAT(t)}
	key := generateTestECDSAKey(t)
	pk := key.Public().(*ecdsa.PublicKey)
	kd := *e.Kat.CertInfo
	sig, err := e.Sign(kd, AlgorithmES256, key)
	require.NoError(t, err)
	err = e.Kat.SetSig(sig)
	require.NoError(t, err)

	pd := *e.Pat.AttestInfo
	sig, err = e.Sign(pd, AlgorithmES256, key)
	require.NoError(t, err)
	err = e.Pat.SetSig(sig)
	require.NoError(t, err)

	err = e.Verify(pk)
	require.NoError(t, err)
}

func TestEvidence_Sign_Verify_nok(t *testing.T) {
	e := &Evidence{Kat: mustBuildValidKAT(t), Pat: mustBuildValidPAT(t)}
	key := generateTestECDSAKey(t)
	pk := key.Public().(*ecdsa.PublicKey)

	kd := *e.Kat.CertInfo

	sig, err := e.Sign(kd, AlgorithmES256, key)
	require.NoError(t, err)
	err = e.Kat.SetSig(sig)
	require.NoError(t, err)

	err = e.Verify(pk)
	expectedErr := "failed to verify signature on platform attestation token: failed to verify the signature: Verification failed"
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_Sign_nok(t *testing.T) {

	e := &Evidence{Kat: mustBuildValidKAT(t), Pat: mustBuildValidPAT(t)}
	key := generateTestECDSAKey(t)

	expectedErr := "unsupported algorithm for signing: 0"
	kd := *e.Kat.CertInfo

	_, err := e.Sign(kd, InValidAlgorithm, key)
	assert.EqualError(t, err, expectedErr)

}
