// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package cca

import (
	"crypto"
	"crypto/sha512"
	"errors"
	"fmt"
	"reflect"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/ccatoken"
)

type Evidence struct {
	Kat    KAT
	Pat    ccatoken.Evidence
	rawKAT []byte
}

func (o *Evidence) FromCBOR(buf []byte) error {
	raw := struct {
		KAT *cbor.RawMessage `cbor:"kat"`
		PAT *cbor.RawMessage `cbor:"pat"`
	}{}

	if err := dm.Unmarshal(buf, &raw); err != nil {
		return fmt.Errorf("CBOR decoding: %w", err)
	}

	if raw.KAT == nil {
		return errors.New("nil KAT")
	} else if err := o.Kat.FromCBOR(*raw.KAT); err != nil {
		return fmt.Errorf("KAT validation: %w", err)
	}

	o.rawKAT = *raw.KAT

	if raw.PAT == nil {
		return errors.New("nil PAT")
	} else {
		pat, err := ccatoken.DecodeAndValidateEvidenceFromCBOR(*raw.PAT)
		if err != nil {
			return fmt.Errorf("PAT validation: %w", err)
		}
		o.Pat = *pat
	}

	return nil
}

func (o Evidence) Verify(pak crypto.PublicKey) error {
	// Verify the CCA token with the PAK
	if err := o.Pat.Verify(pak); err != nil {
		return fmt.Errorf("PAT validation failed: %w", err)
	}

	if err := o.checkBinder(); err != nil {
		return fmt.Errorf("PAT-KAT binding check failed: %w", err)
	}

	return nil
}

func (o Evidence) checkBinder() error {
	got, _ := o.Pat.RealmClaims.GetChallenge()

	h := sha512.New()
	h.Write(o.rawKAT)
	want := h.Sum(nil)

	if !reflect.DeepEqual(want, got) {
		return fmt.Errorf("want %x, got %x", want, got)
	}

	return nil
}
