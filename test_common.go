// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package parsectpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/require"
	"github.com/veraison/eat"
	"github.com/veraison/swid"
)

var (
	testNonce  = []byte("ABABABABABABABABABA")
	testTPMVer = "2.0"
	testPCR    = PCRDetails{
		PCRinfo:   PCRInfo{HashAlgID: swid.Sha256, PCRs: []int{1, 2, 3}},
		PCRDigest: make([]byte, crypto.SHA256.Size()),
	}
	testUEID = eat.UEID{
		0x01, // RAND
		0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
		0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, // 16 bytes
	}
	testInvalidSig = []byte("Invalid Signature")
)

func generateTestECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}
	return key
}

func generateTestRSAKey(t *testing.T) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	return key
}

func KeyFromJWK(t *testing.T, j []byte) crypto.PrivateKey {

	_, key := getAlgAndKeyFromJWK(t, j)

	return key
}

func getAlgAndKeyFromJWK(t *testing.T, j []byte) (Algorithm, crypto.PrivateKey) {
	k, err := jwk.ParseKey(j)
	require.Nil(t, err)

	var (
		key crypto.Signer
		alg Algorithm
	)

	err = k.Raw(&key)
	require.NoError(t, err)

	switch v := key.(type) {
	case *ecdsa.PrivateKey:
		switch v.Curve {
		case elliptic.P256():
			alg = AlgorithmES256
		case elliptic.P384():
			alg = AlgorithmES384
		default:
			require.True(t, false, "unknown elliptic curve")
		}
	default:
		require.True(t, false, "unknown private key type %v", reflect.TypeOf(key))
	}
	return alg, key
}

func pubKeyFromJWK(t *testing.T, j []byte) crypto.PublicKey {
	alg, key := getAlgAndKeyFromJWK(t, j)
	switch alg {
	case AlgorithmES256, AlgorithmES384:
		privkey := key.(*ecdsa.PrivateKey)
		vk := privkey.Public()
		return vk
	default:
		return nil
	}
}
