// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package parsectpm

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"

	cbor "github.com/fxamacker/cbor/v2"
)

// Evidence is a collection of Parsec TPM Key and Platform Attestation objects
type Evidence struct {
	Kat *KAT `cbor:"kat" json:"kat"`
	Pat *PAT `cbor:"pat" json:"pat"`
}

func (e *Evidence) SetTokens(k *KAT, p *PAT) error {
	if err := validateKatPat(k, p); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}
	e.Kat = k
	e.Pat = p
	return nil
}

// ToJSON takes key and platform attestation tokens from Evidence
// and serializes them into valid a JSON
func (e Evidence) ToJSON() ([]byte, error) {
	if err := validateKatPat(e.Kat, e.Pat); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}
	return json.Marshal(e)
}

// FromJSON extracts & validates key and platform attestation tokens from
// the serialized JSON bytes
func (e *Evidence) FromJSON(data []byte) error {
	if err := json.Unmarshal(data, e); err != nil {
		return fmt.Errorf("error unmarshalling Parsec TPM collection: %w", err)
	}
	if err := validateKatPat(e.Kat, e.Pat); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}
	return nil
}

// FromCBOR extracts & validates key and platform attestation token
// from the serialized CBOR collection
func (e *Evidence) FromCBOR(buf []byte) error {
	err := cbor.Unmarshal(buf, e)
	if err != nil {
		return fmt.Errorf("CBOR decoding of Parsec TPM attestation failed %w", err)
	}

	if err := validateKatPat(e.Kat, e.Pat); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}
	return nil
}

// ToCBOR takes key and platform attestation tokens from Evidence
// and serializes them into valid a CBOR
func (e Evidence) ToCBOR() ([]byte, error) {
	if err := validateKatPat(e.Kat, e.Pat); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}
	return cbor.Marshal(e)
}

// Verify verifies the signature on the individual KAT and PAT tokens
func (e Evidence) Verify(key crypto.PublicKey) error {
	if e.Kat == nil {
		return errors.New("missing Parsec TPM key attestation token")
	}
	if e.Pat == nil {
		return errors.New("missing Parsec TPM platform attestation token")
	}
	if err := e.Kat.Verify(key); err != nil {
		return fmt.Errorf("failed to verify signature on key attestation token: %w", err)
	}
	if err := e.Pat.Verify(key); err != nil {
		return fmt.Errorf("failed to verify signature on platform attestation token: %w", err)
	}
	return nil
}

// Sign signs the given data using the supplied algorithm and private key and returns
// signature bytes which is an encoded TPMT_SIGNATURE Structure
func (e Evidence) Sign(data []byte, alg Algorithm, key crypto.PrivateKey) ([]byte, error) {

	switch alg {
	case AlgorithmES256, AlgorithmES384, AlgorithmES512:
		sk, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid key type: %T", sk)
		}
		sig, err := signEcdsa(alg, sk, data)
		if err != nil {
			return nil, fmt.Errorf("Sign failed: %w", err)
		}
		return sig, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm for signing: %d", alg)
	}

}
