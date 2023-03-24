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
	"github.com/veraison/go-cose"
)

func Test_Evidence_FromCBOR_ok(t *testing.T) {
	tokenBytes, err := os.ReadFile("test/evidence.cbor")
	require.NoError(t, err)

	collection := &Evidence{}
	err = collection.FromCBOR(tokenBytes)
	require.NoError(t, err)
}

func Test_Evidence_FromCBOR_nok(t *testing.T) {
	tokenBytes, err := os.ReadFile("test/bad_evidence.cbor")
	require.NoError(t, err)
	expectedErr := "CBOR decoding of Parsec TPM attestation failed cbor: invalid additional information 28 for type byte string"
	collection := &Evidence{}
	err = collection.FromCBOR(tokenBytes)
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_ToCBOR_ok(t *testing.T) {
	var EvidenceIn Evidence
	err := EvidenceIn.SetTokens(
		mustBuildValidKAT(t),
		mustBuildValidPAT(t),
	)
	require.NoError(t, err)

	_, err = EvidenceIn.ToCBOR()
	require.NoError(t, err)
}

func TestEvidence_ToCBOR_InvalidPat(t *testing.T) {
	var EvidenceIn Evidence
	p := buildInValidPAT(t)
	k := mustBuildValidKAT(t)
	EvidenceIn.collection = &Collection{Kat: k, Pat: p}
	expectedErr := "validation of platform attestation token failed missing key identifier"
	_, err := EvidenceIn.ToCBOR()
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_ToCBOR_InvalidKat(t *testing.T) {
	var EvidenceIn Evidence
	p := mustBuildValidPAT(t)
	k := buildInValidKAT(t)
	EvidenceIn.collection = &Collection{Kat: k, Pat: p}
	expectedErr := "validation of key attestation token failed missing signature"
	_, err := EvidenceIn.ToCBOR()
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_ToCBOR_MissingPat(t *testing.T) {
	var EvidenceIn Evidence
	k := mustBuildValidKAT(t)
	EvidenceIn.collection = &Collection{Kat: k}
	expectedErr := "missing platform attestation token"
	_, err := EvidenceIn.ToCBOR()
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_ToCBOR_MissingKat(t *testing.T) {
	var EvidenceIn Evidence
	p := mustBuildValidPAT(t)
	EvidenceIn.collection = &Collection{Pat: p}
	expectedErr := "missing key attestation token"
	_, err := EvidenceIn.ToCBOR()
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_MarshalJSON_ok(t *testing.T) {
	var EvidenceIn Evidence
	err := EvidenceIn.SetTokens(
		mustBuildValidKAT(t),
		mustBuildValidPAT(t),
	)
	require.NoError(t, err)

	data, err := EvidenceIn.MarshalJSON()
	fmt.Printf("%s", data)
	require.NoError(t, err)
}

func TestEvidence_MarshalJSON_InvalidPat(t *testing.T) {
	var EvidenceIn Evidence
	p := buildInValidPAT(t)
	k := mustBuildValidKAT(t)
	EvidenceIn.collection = &Collection{Kat: k, Pat: p}
	expectedErr := "validation of platform attestation token failed missing key identifier"
	_, err := EvidenceIn.MarshalJSON()
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_MarshalJSON_InvalidKat(t *testing.T) {
	var EvidenceIn Evidence
	p := mustBuildValidPAT(t)
	k := buildInValidKAT(t)
	EvidenceIn.collection = &Collection{Kat: k, Pat: p}
	expectedErr := "validation of key attestation token failed missing signature"
	_, err := EvidenceIn.MarshalJSON()
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_MarshalJSON_missingPat(t *testing.T) {
	var EvidenceIn Evidence
	k := mustBuildValidKAT(t)
	EvidenceIn.collection = &Collection{Kat: k}
	expectedErr := "missing platform attestation token"
	_, err := EvidenceIn.MarshalJSON()
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_MarshalJSON_missingKat(t *testing.T) {
	var EvidenceIn Evidence
	p := mustBuildValidPAT(t)
	EvidenceIn.collection = &Collection{Pat: p}
	expectedErr := "missing key attestation token"
	_, err := EvidenceIn.MarshalJSON()
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_UnMarshalJSON_ok(t *testing.T) {
	tokenBytes, err := os.ReadFile("test/evidence.json")
	require.NoError(t, err)

	collection := &Evidence{}
	err = collection.UnmarshalJSON(tokenBytes)
	require.NoError(t, err)
}

func TestEvidence_UnMarshalJSON_missing_pat(t *testing.T) {
	tokenBytes, err := os.ReadFile("test/evidence_missing_pat.json")
	require.NoError(t, err)

	expectedErr := "Parsec TPM platform attestation token not set"
	collection := &Evidence{}
	err = collection.UnmarshalJSON(tokenBytes)
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_UnMarshalJSON_missing_kat(t *testing.T) {
	tokenBytes, err := os.ReadFile("test/evidence_missing_kat.json")
	require.NoError(t, err)

	expectedErr := "Parsec TPM key attestation token not set"
	collection := &Evidence{}
	err = collection.UnmarshalJSON(tokenBytes)
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_UnMarshalJSON_invalid_pat(t *testing.T) {
	tokenBytes, err := os.ReadFile("test/evidence_invalid_pat.json")
	require.NoError(t, err)

	expectedErr := "validation of platform attestation token failed missing key identifier"
	collection := &Evidence{}
	err = collection.UnmarshalJSON(tokenBytes)
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_UnMarshalJSON_invalid_kat(t *testing.T) {
	tokenBytes, err := os.ReadFile("test/evidence_invalid_kat.json")
	require.NoError(t, err)

	expectedErr := "validation of key attestation token failed missing public key information"
	collection := &Evidence{}
	err = collection.UnmarshalJSON(tokenBytes)
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_SetTokens_invalidPat(t *testing.T) {
	var EvidenceIn Evidence
	err := EvidenceIn.SetTokens(
		mustBuildValidKAT(t),
		buildInValidPAT(t),
	)
	expectedErr := "validation of platform attestation token failed: missing key identifier"
	assert.EqualError(t, err, expectedErr)

}

func TestEvidence_SetTokens_invalidKat(t *testing.T) {
	var EvidenceIn Evidence
	err := EvidenceIn.SetTokens(
		buildInValidKAT(t),
		mustBuildValidPAT(t),
	)
	expectedErr := "validation of key attestation token failed: missing signature"
	assert.EqualError(t, err, expectedErr)

}
func TestEvidence_SetTokens_missingKat(t *testing.T) {
	var EvidenceIn Evidence
	err := EvidenceIn.SetTokens(
		nil,
		mustBuildValidPAT(t),
	)
	expectedErr := "nil token supplied"
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_Verify_missingCollection(t *testing.T) {
	var EvidenceIn Evidence
	key := generateTestECDSAKey(t)
	pk := key.Public().(*ecdsa.PublicKey)

	err := EvidenceIn.Verify(pk)
	expectedErr := "missing collection"
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_Verify_missingKat(t *testing.T) {
	var EvidenceIn Evidence
	EvidenceIn.collection = &Collection{Pat: mustBuildValidPAT(t)}
	key := generateTestECDSAKey(t)
	pk := key.Public().(*ecdsa.PublicKey)

	err := EvidenceIn.Verify(pk)
	expectedErr := "missing Parsec TPM key attestation token"
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_Verify_missingPat(t *testing.T) {
	var EvidenceIn Evidence
	EvidenceIn.collection = &Collection{Kat: mustBuildValidKAT(t)}
	key := generateTestECDSAKey(t)
	pk := key.Public().(*ecdsa.PublicKey)

	err := EvidenceIn.Verify(pk)
	expectedErr := "missing Parsec TPM platform attestation token"
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_Verify_ECKey_Failed(t *testing.T) {
	var EvidenceIn Evidence
	EvidenceIn.collection = &Collection{Kat: mustBuildValidKAT(t), Pat: mustBuildValidPAT(t)}
	key := generateTestECDSAKey(t)
	pk := key.Public().(*ecdsa.PublicKey)

	err := EvidenceIn.Verify(pk)
	expectedErr := "failed to verify signature on key attestation token: failed to verify signature Verification failed"
	assert.EqualError(t, err, expectedErr)

}

func TestEvidence_Verify_RSAKey_Failed(t *testing.T) {
	var EvidenceIn Evidence
	EvidenceIn.collection = &Collection{Kat: mustBuildValidKAT(t), Pat: mustBuildValidPAT(t)}
	key := generateTestRSAKey(t)
	pk := key.Public().(*rsa.PublicKey)

	err := EvidenceIn.Verify(pk)
	expectedErr := "failed to verify signature on key attestation token: failed to verify signature invalid public key for algorithm: ECDSA"
	assert.EqualError(t, err, expectedErr)

}
func TestEvidence_Sign_Verify_ok(t *testing.T) {
	var EvidenceIn Evidence
	EvidenceIn.collection = &Collection{Kat: mustBuildValidKAT(t), Pat: mustBuildValidPAT(t)}
	key := generateTestECDSAKey(t)
	pk := key.Public().(*ecdsa.PublicKey)

	kd := *EvidenceIn.collection.Kat.CertInfo

	sig, err := EvidenceIn.Sign(kd, cose.AlgorithmES256, key)
	require.NoError(t, err)
	err = EvidenceIn.collection.Kat.SetSig(sig)
	require.NoError(t, err)

	pd := *EvidenceIn.collection.Pat.AttestInfo
	sig, err = EvidenceIn.Sign(pd, cose.AlgorithmES256, key)
	require.NoError(t, err)
	err = EvidenceIn.collection.Pat.SetSig(sig)
	require.NoError(t, err)

	err = EvidenceIn.Verify(pk)
	require.NoError(t, err)
}

func TestEvidence_Sign_Verify_nok(t *testing.T) {
	var EvidenceIn Evidence
	EvidenceIn.collection = &Collection{Kat: mustBuildValidKAT(t), Pat: mustBuildValidPAT(t)}
	key := generateTestECDSAKey(t)
	pk := key.Public().(*ecdsa.PublicKey)

	kd := *EvidenceIn.collection.Kat.CertInfo

	sig, err := EvidenceIn.Sign(kd, cose.AlgorithmES256, key)
	require.NoError(t, err)
	err = EvidenceIn.collection.Kat.SetSig(sig)
	require.NoError(t, err)

	err = EvidenceIn.Verify(pk)
	expectedErr := "failed to verify signature on platform attestation token: failed to verify the signature Verification failed"
	assert.EqualError(t, err, expectedErr)
}

func TestEvidence_Sign_nok(t *testing.T) {
	var EvidenceIn Evidence
	EvidenceIn.collection = &Collection{Kat: mustBuildValidKAT(t), Pat: mustBuildValidPAT(t)}
	key := generateTestECDSAKey(t)

	expectedErr := "unsupported algorithm for signing: -37"
	kd := *EvidenceIn.collection.Kat.CertInfo

	_, err := EvidenceIn.Sign(kd, cose.AlgorithmPS256, key)
	assert.EqualError(t, err, expectedErr)

}
