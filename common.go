// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package parsectpm

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"

	tpm2 "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/veraison/eat"
	"github.com/veraison/swid"
)

const (
	DefaultTPMHandle = tpmutil.Handle(100)
	TpmMagic         = 0xff544347
)

// Algorithms supported by this library

type Algorithm uint16

const (
	InValidAlgorithm = 0
	AlgorithmES256   = 1
	AlgorithmES384   = 2
	AlgorithmES512   = 3
)

func NewTpmAttestDefault() tpm2.AttestationData {
	ad := tpm2.AttestationData{}
	signer := DefaultTPMHandle
	ad.ClockInfo = tpm2.ClockInfo{
		Clock:        3,
		ResetCount:   4,
		RestartCount: 5,
		Safe:         6,
	}
	ad.FirmwareVersion = 7
	ad.QualifiedSigner = tpm2.Name{
		Handle: &signer}
	return ad
}

func computeHash(alg tpm2.Algorithm, data []byte) ([]byte, error) {
	h, err := alg.Hash()
	if err != nil {
		return nil, fmt.Errorf("unable to compute hash for algorthm: %d, reason: %w", alg, err)
	}

	hh := h.New()
	if _, err := hh.Write(data); err != nil {
		return nil, err
	}
	return hh.Sum(nil), nil
}

func mapAlgToTpmHash(alg Algorithm) tpm2.Algorithm {
	var ta tpm2.Algorithm
	switch alg {
	case AlgorithmES256:
		ta = tpm2.AlgSHA256
	case AlgorithmES384:
		ta = tpm2.AlgSHA384
	case AlgorithmES512:
		ta = tpm2.AlgSHA512
	default:
		ta = tpm2.AlgUnknown
	}
	return ta
}

func swidHashAlgToTPMAlg(algID uint64) tpm2.Algorithm {
	switch algID {
	case swid.Sha256:
		return tpm2.AlgSHA256
	case swid.Sha384:
		return tpm2.AlgSHA384
	case swid.Sha512:
		return tpm2.AlgSHA512
	case swid.Sha3_256:
		return tpm2.AlgSHA3_256
	case swid.Sha3_384:
		return tpm2.AlgSHA3_384
	case swid.Sha3_512:
		return tpm2.AlgSHA3_512
	default:
		return tpm2.AlgUnknown
	}
}

func tpmHashAlgToSWIDHash(algID tpm2.Algorithm) uint64 {
	switch algID {
	case tpm2.AlgSHA256:
		return swid.Sha256
	case tpm2.AlgSHA384:
		return swid.Sha384
	case tpm2.AlgSHA512:
		return swid.Sha512
	case tpm2.AlgSHA3_256:
		return swid.Sha3_256
	case tpm2.AlgSHA3_384:
		return swid.Sha3_384
	case tpm2.AlgSHA3_512:
		return swid.Sha3_512
	default:
		return UnSupportedAlg
	}
}

func verify(key crypto.PublicKey, data []byte, sig []byte) error {
	s, err := tpm2.DecodeSignature(bytes.NewBuffer(sig))
	if err != nil {
		return fmt.Errorf("unable to decode the signature: %w", err)
	}
	alg := s.Alg

	switch alg {
	case tpm2.AlgECDSA:
		vk, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("invalid public key type: %T", key)
		}

		ha := s.ECC.HashAlg
		hdata, err := computeHash(ha, data)
		if err != nil {
			return fmt.Errorf("unable to compute hash for input data: %w", err)
		}

		verified := ecdsa.Verify(vk, hdata, s.ECC.R, s.ECC.S)
		if !verified {
			return errors.New("Verification failed")

		}
	default:
		return fmt.Errorf("unsupported signature algorithm %d", alg)
	}
	return nil
}

func signEcdsa(alg Algorithm, key *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	ta := mapAlgToTpmHash(alg)
	hash, err := computeHash(ta, data)
	if err != nil {
		return nil, fmt.Errorf("unable to compute hash: %w", err)
	}
	r, s, err := ecdsa.Sign(rand.Reader, key, hash)
	if err != nil {
		return nil, fmt.Errorf("ecdsa signing failed: %w", err)
	}
	sig := tpm2.Signature{
		Alg: tpm2.AlgECDSA,
		ECC: &tpm2.SignatureECC{
			HashAlg: ta,
			R:       r,
			S:       s,
		},
	}
	e, err := sig.Encode()
	if err != nil {
		return nil, fmt.Errorf("signature encoding failed: %w", err)
	}
	return e, nil
}

func validateKID(v []byte) error {
	data := eat.UEID(v)
	if err := data.Validate(); err != nil {
		return fmt.Errorf("failed to validate UEID: %w", err)
	}
	return nil
}

func validateKatPat(k *KAT, p *PAT) error {
	if k == nil {
		return errors.New("nil key attestation token supplied")
	}
	if err := k.Validate(); err != nil {
		return fmt.Errorf("validation of key attestation token failed: %w", err)
	}

	if p == nil {
		return errors.New("nil platform attestation token supplied")
	}
	if err := p.Validate(); err != nil {
		return fmt.Errorf("validation of platform attestation token failed: %w", err)
	}
	if !bytes.Equal(*k.KID, *p.KID) {
		return fmt.Errorf("KID mismatch KAT: %x and PAT: %x", *k.KID, *p.KID)
	}
	return nil
}
