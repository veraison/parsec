// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package parsectpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/veraison/eat"
	"github.com/veraison/swid"
)

var (
	testNonce  = []byte("ABABABABABABABABABA")
	testTPMVer = "2.0"
	testMagic  = 0xff544347
	testAlg    = swid.Sha256
	testPCR    = PCRDetails{
		PCRinfo:   PCRInfo{HashAlgID: swid.Sha256, PCRs: []int{1, 2, 3}},
		PCRDigest: make([]byte, crypto.SHA256.Size()),
	}
	testHandle1 = 1
	testHandle2 = 2
	testName    = NameInfo{
		Handle:  uint32(testHandle1),
		DigInfo: DigestInfo{HashAlgID: swid.Sha256, Digest: make([]byte, crypto.SHA256.Size())}}

	testQualName = NameInfo{
		Handle:  uint32(testHandle2),
		DigInfo: DigestInfo{HashAlgID: swid.Sha256, Digest: make([]byte, crypto.SHA256.Size())}}

	testCertInfo = TpmCertInfo{Name: testName, QualifiedName: testQualName}
	testUEID     = eat.UEID{
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
