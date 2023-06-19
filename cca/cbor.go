// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package cca

import (
	"reflect"

	cbor "github.com/fxamacker/cbor/v2"
)

var (
	dm, dmInitError = initCBORDecoder()
)

func uccsTag() cbor.TagSet {
	tagSet := cbor.NewTagSet()

	if err := tagSet.Add(
		cbor.TagOptions{
			EncTag: cbor.EncTagRequired,
			DecTag: cbor.DecTagRequired,
		},
		reflect.TypeOf(KAT{}),
		601,
	); err != nil {
		panic(err)
	}

	return tagSet
}

func initCBORDecoder() (cbor.DecMode, error) {
	decOpts := cbor.DecOptions{
		IndefLength: cbor.IndefLengthForbidden,
	}

	return decOpts.DecModeWithTags(uccsTag())
}

func init() {
	if dmInitError != nil {
		panic(dmInitError)
	}
}
