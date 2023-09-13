// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package cca

import (
	"errors"
	"fmt"

	"github.com/veraison/eat"
	cose "github.com/veraison/go-cose"
)

type KAT struct {
	Nonce *eat.Nonce `cbor:"10,keyasint,omitempty"`
	Cnf   *CNF       `cbor:"8,keyasint,omitempty"`
}

type CNF struct {
	COSEKey cose.Key `cbor:"1,keyasint,omitempty"`
}

func (o *KAT) FromCBOR(b []byte) error {
	if err := dm.Unmarshal(b, o); err != nil {
		return fmt.Errorf("KAT decoding failed: %w", err)
	}

	if err := o.Validate(); err != nil {
		return fmt.Errorf("KAT validation failed: %w", err)
	}

	return nil
}

func (o KAT) Validate() error {
	if o.Nonce == nil {
		return errors.New("nonce claim missing")
	} else if err := o.Nonce.Validate(); err != nil {
		return fmt.Errorf("nonce validation failed: %w", err)
	}

	if o.Cnf == nil {
		return errors.New("cnf claim missing")
	}

	return nil
}
