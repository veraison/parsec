// Copyright 2022 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package parsectpm

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"os"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cose "github.com/veraison/go-cose"
)

func mustBuildValidKAT(t *testing.T) *KAT {
	k := NewKAT()
	err := k.SetTpmVer(testTPMVer)
	require.NoError(t, err)

	err = k.SetAlg(testAlg)
	require.NoError(t, err)

	err = k.SetKeyID(testUEID)
	require.NoError(t, err)

	sig, err := genSigBytes()
	require.NoError(t, err)
	err = k.SetSig(sig)
	require.NoError(t, err)

	certInfo := CertInfo{}
	certInfo.Magic = uint32(testMagic)
	certInfo.Nonce = testNonce
	certInfo.TpmCertInfo = testCertInfo
	certInfo.Type = uint16(tpm2.TagAttestCertify)
	err = k.EncodeCertInfo(certInfo)
	require.NoError(t, err)

	key := generateTestECDSAKey(t)
	pk := key.Public().(*ecdsa.PublicKey)

	err = k.EncodePubArea(cose.AlgorithmES256, pk)
	require.NoError(t, err)
	return k
}

func buildInValidKAT(t *testing.T) *KAT {
	k := NewKAT()
	err := k.SetTpmVer(testTPMVer)
	require.NoError(t, err)

	err = k.SetAlg(testAlg)
	require.NoError(t, err)

	err = k.SetKeyID(testUEID)
	require.NoError(t, err)

	certInfo := CertInfo{}
	certInfo.Magic = uint32(testMagic)
	certInfo.Nonce = testNonce
	certInfo.TpmCertInfo = testCertInfo
	certInfo.Type = uint16(tpm2.TagAttestCertify)
	err = k.EncodeCertInfo(certInfo)
	require.NoError(t, err)

	key := generateTestECDSAKey(t)
	pk := key.Public().(*ecdsa.PublicKey)

	err = k.EncodePubArea(cose.AlgorithmES256, pk)
	require.NoError(t, err)
	return k
}

func Test_KAT_DecodePublicArea_ok(t *testing.T) {
	tokenBytes, err := os.ReadFile("test/evidence.cbor")
	require.NoError(t, err)

	e := &Evidence{}
	err = e.FromCBOR(tokenBytes)
	require.NoError(t, err)

	at, err := e.collection.Kat.DecodePubArea()
	require.NoError(t, err)
	fmt.Printf("received public key %x", at)
	require.NoError(t, err)
}

func Test_KAT_EncodePublicArea_ok(t *testing.T) {
	k := &KAT{}

	key := generateTestRSAKey(t)
	pk := key.Public().(*rsa.PublicKey)

	err := k.EncodePubArea(cose.AlgorithmPS256, pk)
	require.NoError(t, err)
}

func Test_KAT_DecodeCertInfo_ok(t *testing.T) {
	tokenBytes, err := os.ReadFile("test/evidence.cbor")
	require.NoError(t, err)

	e := &Evidence{}
	err = e.FromCBOR(tokenBytes)
	require.NoError(t, err)

	at, err := e.collection.Kat.DecodeCertInfo()
	require.NoError(t, err)
	fmt.Printf("received public key %x", at)
	require.NoError(t, err)
}

func Test_KAT_Validate_MissingTPMVer(t *testing.T) {
	k := &KAT{}
	expectedErr := "TPM Version not set"
	err := k.Validate()
	assert.EqualError(t, err, expectedErr)

	tv := ""
	k.TpmVer = &tv
	expectedErr = "Empty TPM Version"
	err = k.Validate()
	assert.EqualError(t, err, expectedErr)
}

func Test_KAT_Validate_InvalidKID(t *testing.T) {
	k := &KAT{}
	err := k.SetTpmVer("TPM 2.0")
	require.NoError(t, err)
	data := []byte("AAAAAAA")
	k.KID = &data
	expectedErr := "invalid KID : failed to validate UEID: invalid UEID type 65"
	err = k.Validate()
	assert.EqualError(t, err, expectedErr)
}
