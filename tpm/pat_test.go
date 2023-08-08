// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package tpm

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"testing"

	tpm2 "github.com/google/go-tpm/legacy/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustBuildValidPAT(t *testing.T) *PAT {
	p := NewPAT()

	err := p.SetTpmVer(testTPMVer)
	require.NoError(t, err)

	err = p.SetKeyID(testUEID)
	require.NoError(t, err)

	sig, err := genSigBytes()
	require.NoError(t, err)
	err = p.SetSig(sig)
	require.NoError(t, err)

	attInfo := &AttestationInfo{}
	attInfo.Nonce = testNonce
	attInfo.PCR = testPCR

	err = p.EncodeAttestationInfo(attInfo)
	require.NoError(t, err)

	return p

}

func buildInValidPAT(t *testing.T) *PAT {
	p := NewPAT()

	err := p.SetTpmVer(testTPMVer)
	require.NoError(t, err)

	sig, err := genSigBytes()
	require.NoError(t, err)
	err = p.SetSig(sig)
	require.NoError(t, err)

	attInfo := &AttestationInfo{}
	attInfo.Nonce = testNonce
	attInfo.PCR = testPCR

	err = p.EncodeAttestationInfo(attInfo)
	require.NoError(t, err)

	return p

}

func genSigBytes() ([]byte, error) {
	size := 32
	randBytes := make([]byte, size)
	_, err := rand.Read(randBytes)
	if err != nil {
		return nil, fmt.Errorf("read failed for bytes: %w", err)
	}
	r := big.NewInt(0).SetBytes(randBytes)

	_, err = rand.Read(randBytes)
	if err != nil {
		return nil, fmt.Errorf("read failed for bytes: %w", err)
	}

	s := big.NewInt(0).SetBytes(randBytes)
	sig := tpm2.Signature{
		Alg: tpm2.AlgECDSA,
		ECC: &tpm2.SignatureECC{
			HashAlg: tpm2.AlgSHA256,
			R:       r,
			S:       s,
		},
	}
	e, err := sig.Encode()
	if err != nil {
		return nil, fmt.Errorf("Signature{%+v}.Encode() returned error: %v", s, err)
	}
	return e, nil
}

func Test_PAT_DecodeAttestInfo_ok(t *testing.T) {
	tokenBytes, err := os.ReadFile("test/evidence.cbor")
	require.NoError(t, err)

	e := &Evidence{}
	err = e.FromCBOR(tokenBytes)
	require.NoError(t, err)

	at, err := e.Pat.GetAttestationInfo()
	require.NoError(t, err)
	fmt.Printf("received attestation information %x", at.Nonce)
	require.NoError(t, err)
}

func Test_PAT_Validate(t *testing.T) {
	p := &PAT{}
	attInfo := &AttestationInfo{}
	attInfo.Nonce = testNonce
	attInfo.PCR = testPCR

	err := p.SetTpmVer(testTPMVer)
	require.NoError(t, err)

	err = p.SetKeyID(testUEID)
	require.NoError(t, err)
	err = p.EncodeAttestationInfo(attInfo)
	require.NoError(t, err)

	sig, err := genSigBytes()
	require.NoError(t, err)
	err = p.SetSig(sig)
	require.NoError(t, err)

	err = p.Validate()
	require.NoError(t, err)

}

func Test_PAT_Validate_InvalidSig(t *testing.T) {
	p := &PAT{}
	p.TpmVer = &testTPMVer
	d := []byte(testUEID)
	p.KID = &d
	p.Sig = &testInvalidSig
	expectedErr := "not a valid signature: unsupported signature algorithm 0x416c673f3c31383739383e"
	err := p.Validate()
	assert.EqualError(t, err, expectedErr)
}

func Test_PAT_Validate_MissingTPMVer(t *testing.T) {
	p := &PAT{}
	expectedErr := "TPM Version not set"
	err := p.Validate()
	assert.EqualError(t, err, expectedErr)

	tv := ""
	p.TpmVer = &tv
	expectedErr = "Empty TPM Version"
	err = p.Validate()
	assert.EqualError(t, err, expectedErr)

}

func Test_PAT_Validate_InvalidKID(t *testing.T) {
	p := &PAT{}
	err := p.SetTpmVer("TPM 2.0")
	require.NoError(t, err)
	data := []byte("AAAAAAA")
	p.KID = &data
	expectedErr := "invalid KID: failed to validate UEID: invalid UEID type 65"
	err = p.Validate()
	assert.EqualError(t, err, expectedErr)
}

func Test_PAT_SetTpmVer_nok(t *testing.T) {
	p := &PAT{}
	expectedErr := "empty string supplied"
	err := p.SetTpmVer("")
	assert.EqualError(t, err, expectedErr)
}

func Test_PAT_SetKeyID_nok(t *testing.T) {
	p := &PAT{}
	kid := []byte("RandomGenerator")
	expectedErr := "invalid KID: failed to validate UEID: invalid UEID type 82"
	err := p.SetKeyID(kid)
	assert.EqualError(t, err, expectedErr)
}

func Test_PAT_SetSig_nok(t *testing.T) {
	p := &PAT{}
	sig := []byte("")
	expectedErr := "zero len signature bytes"
	err := p.SetSig(sig)
	assert.EqualError(t, err, expectedErr)
}
