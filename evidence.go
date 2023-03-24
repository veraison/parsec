// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package parsectpm

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"

	cbor "github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

type Collection struct {
	Kat *KAT `cbor:"kat" json:"kat"`
	Pat *PAT `cbor:"pat" json:"pat"`
}

// Evidence is a wrapper around TpmParsec Attestation Collection
type Evidence struct {
	collection *Collection
}

func (e *Evidence) SetTokens(k *KAT, p *PAT) error {

	if k == nil || p == nil {
		return fmt.Errorf("nil token supplied")
	}

	if err := k.Validate(); err != nil {
		return fmt.Errorf("validation of key attestation token failed: %w", err)
	}

	if err := p.Validate(); err != nil {
		return fmt.Errorf("validation of platform attestation token failed: %w", err)
	}

	e.collection = &Collection{
		Kat: k,
		Pat: p,
	}

	return nil
}

// MarshalJSON takes key and platform attestation tokens from Evidence
// and serializes them into valid a JSON
func (e *Evidence) MarshalJSON() ([]byte, error) {

	if e.collection.Kat == nil {
		return nil, errors.New("missing key attestation token")
	}

	k := e.collection.Kat
	if err := k.Validate(); err != nil {
		return nil, fmt.Errorf("validation of key attestation token failed %w", err)
	}

	if e.collection.Pat == nil {
		return nil, errors.New("missing platform attestation token")
	}

	p := e.collection.Pat
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("validation of platform attestation token failed %w", err)
	}
	return json.Marshal(e.collection)
}

// UnmarshalJSON extracts & validates key and platform attestation tokens from
// the serialized JSON collection
func (e *Evidence) UnmarshalJSON(data []byte) error {
	e.collection = &Collection{}

	if err := json.Unmarshal(data, e.collection); err != nil {
		return fmt.Errorf("error unmarshalling Parsec TPM collection %w", err)
	}

	if e.collection.Kat == nil {
		return fmt.Errorf("Parsec TPM key attestation token not set")
	}
	k := e.collection.Kat
	if err := k.Validate(); err != nil {
		return fmt.Errorf("validation of key attestation token failed %w", err)
	}

	if e.collection.Pat == nil {
		return fmt.Errorf("Parsec TPM platform attestation token not set")
	}

	p := e.collection.Pat
	if err := p.Validate(); err != nil {
		return fmt.Errorf("validation of platform attestation token failed %w", err)
	}

	return nil
}

// FromCBOR extracts & validates key and platform attestation token
// from the serialized CBOR collection
func (e *Evidence) FromCBOR(buf []byte) error {
	e.collection = &Collection{}

	err := cbor.Unmarshal(buf, e.collection)
	if err != nil {
		return fmt.Errorf("CBOR decoding of Parsec TPM attestation failed %w", err)
	}

	if e.collection.Kat == nil {
		return fmt.Errorf("TPM Parsec key attestation token not set")
	}
	k := e.collection.Kat
	if err := k.Validate(); err != nil {
		return fmt.Errorf("validation of key attestation token failed %w", err)
	}

	if e.collection.Pat == nil {
		return fmt.Errorf("TPM Parsec platform attestation token not set")
	}

	p := e.collection.Pat
	if err := p.Validate(); err != nil {
		return fmt.Errorf("validation of platform attestation token failed %w", err)
	}

	return nil
}

// ToCBOR takes key and platform attestation tokens from Evidence
// and serializes them into valid a CBOR
func (e *Evidence) ToCBOR() ([]byte, error) {

	if e.collection.Kat == nil {
		return nil, errors.New("missing key attestation token")
	}

	k := e.collection.Kat
	if err := k.Validate(); err != nil {
		return nil, fmt.Errorf("validation of key attestation token failed %w", err)
	}

	if e.collection.Pat == nil {
		return nil, errors.New("missing platform attestation token")
	}

	p := e.collection.Pat
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("validation of platform attestation token failed %w", err)
	}
	return cbor.Marshal(e.collection)
}

// Verify verifies the signature on the individual KAT and PAT tokens
func (e Evidence) Verify(key crypto.PublicKey) error {

	if e.collection == nil {
		return fmt.Errorf("missing collection")
	}
	if e.collection.Kat == nil {
		return fmt.Errorf("missing Parsec TPM key attestation token")
	}

	if e.collection.Pat == nil {
		return fmt.Errorf("missing Parsec TPM platform attestation token")
	}
	if err := e.collection.Kat.Verify(key); err != nil {
		return fmt.Errorf("failed to verify signature on key attestation token: %w", err)
	}
	if err := e.collection.Pat.Verify(key); err != nil {
		return fmt.Errorf("failed to verify signature on platform attestation token: %w", err)
	}
	return nil
}

// Sign creates a TPMS Signature bytes by signing over the given data by
// key supplied by key paramter
func (e Evidence) Sign(data []byte, alg cose.Algorithm, key crypto.PrivateKey) ([]byte, error) {

	switch alg {
	case cose.AlgorithmES256, cose.AlgorithmES384, cose.AlgorithmES512:
		sig, err := signEcdsa(alg, key, data)
		if err != nil {
			return nil, fmt.Errorf("Sign failed %w", err)
		}
		return sig, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm for signing: %d", alg)
	}

}
