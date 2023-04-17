// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package parsectpm

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"reflect"

	tpm2 "github.com/google/go-tpm/tpm2"
)

type KAT struct {
	TpmVer   *string `cbor:"tpmVer" json:"tpmVer"`
	KID      *[]byte `cbor:"kid" json:"kid"`
	Sig      *[]byte `cbor:"sig" json:"sig"`
	PubArea  *[]byte `cbor:"pubArea" json:"pubArea"`
	CertInfo *[]byte `cbor:"certInfo" json:"certInfo"`
}

func NewKAT() *KAT {
	return &KAT{}
}

func (k *KAT) SetTpmVer(v string) error {
	if v == "" {
		return errors.New("empty string supplied")
	}
	k.TpmVer = &v
	return nil
}

func (k *KAT) SetKeyID(v []byte) error {
	if err := validateKID(v); err != nil {
		return fmt.Errorf("invalid KID: %w", err)
	}

	k.KID = &v
	return nil
}

func (k *KAT) SetSig(s []byte) error {
	if len(s) == 0 {
		return errors.New("zero len signature bytes")
	}
	k.Sig = &s
	return nil
}

func (k KAT) Validate() error {
	if k.TpmVer == nil {
		return errors.New("TPM Version not set")
	} else if *k.TpmVer == "" {
		return errors.New("Empty TPM Version")
	}

	if k.KID == nil {
		return errors.New("missing key identifier")
	}
	if err := validateKID(*k.KID); err != nil {
		return fmt.Errorf("invalid KID: %w", err)
	}

	if k.Sig == nil {
		return errors.New("missing signature")
	}
	// Check the signature decode results in a success or not?
	sig, err := tpm2.DecodeSignature(bytes.NewBuffer(*k.Sig))
	if err != nil {
		return fmt.Errorf("not a valid signature: %w", err)
	}
	if sig.Alg != tpm2.AlgECDSA {
		return fmt.Errorf("unsupported signature algorithm: %d", sig.Alg)
	}
	if err := k.validateCertAndPub(); err != nil {
		return fmt.Errorf("validation of cert & pub info failed: %w", err)
	}
	return nil
}

type DigestInfo struct {
	HashAlgID uint64
	Digest    []byte
}

type CertInfo struct {
	Nonce []byte
	Name  DigestInfo
}

func (k KAT) DecodeCertInfo() (*CertInfo, error) {
	certInfo := &CertInfo{}

	if k.CertInfo == nil {
		return nil, errors.New("no certification information in KAT to decode")
	}

	ad, err := tpm2.DecodeAttestationData(*k.CertInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to decode supplied attestation information: %w", err)
	}

	if ad.AttestedCertifyInfo == nil {
		return nil, errors.New("no certify information in the TPMS Attest")
	}

	certInfo.Nonce = ad.ExtraData
	if ad.AttestedCertifyInfo.Name.Digest == nil {
		return nil, errors.New("no digest information in certify info")
	}
	dig, err := getDigestInfo(ad.AttestedCertifyInfo.Name)
	if err != nil {
		return nil, fmt.Errorf("invalid name in certify info: = %w", err)
	}
	certInfo.Name = *dig

	return certInfo, nil
}

func getDigestInfo(name tpm2.Name) (*DigestInfo, error) {
	digestInfo := &DigestInfo{}

	if name.Handle != nil {
		return nil, fmt.Errorf("unexpected handle: %d, received in the name field", name.Handle)
	}

	alg := tpmHashAlgToSWIDHash(name.Digest.Alg)
	if alg == UnSupportedAlg {
		return nil, fmt.Errorf("unknown hash algorithm identifier: %d", name.Digest.Alg)
	}
	digestInfo.HashAlgID = alg
	digestInfo.Digest = name.Digest.Value

	return digestInfo, nil
}

// DecodePubArea decodes a given public key, from TPMT_PUBLIC structure
func (k KAT) DecodePubArea() (crypto.PublicKey, error) {
	if k.PubArea == nil {
		return nil, errors.New("no PubArea to decode")
	}
	pub, err := tpm2.DecodePublic(*k.PubArea)
	if err != nil {
		return nil, fmt.Errorf("unable to decode the Public Area: %w", err)
	}
	pk, err := pub.Key()
	if err != nil {
		return nil, fmt.Errorf("unable to get crypto public key from TPM2 public key: %w", err)
	}
	return pk, nil
}

// Verify verifies the signature on the given key attestation token
// using supplied Public Key
func (k KAT) Verify(key crypto.PublicKey) error {

	if k.CertInfo == nil || len(*k.CertInfo) == 0 {
		return errors.New("no payload content to verify")
	}

	if k.Sig == nil || len(*k.Sig) == 0 {
		return errors.New("no signature on the key attestation token")
	}
	err := verify(key, *k.CertInfo, *k.Sig)
	if err != nil {
		return fmt.Errorf("failed to verify signature: %w", err)
	}
	return nil
}

func (k *KAT) EncodePubArea(alg Algorithm, key crypto.PublicKey) error {

	switch alg {
	case AlgorithmES256, AlgorithmES384, AlgorithmES512:
		ek, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("invalid ECDSA public key type: %T", key)
		}

		if !ek.Curve.IsOnCurve(ek.X, ek.Y) {
			return errors.New("public key is not on the curve")
		}

		// Only following four curves are supported by TPM2
		var curve tpm2.EllipticCurve
		var hashAlg tpm2.Algorithm

		switch ek.Curve {
		case elliptic.P224():
			curve = tpm2.CurveNISTP224
			hashAlg = tpm2.AlgSHA1
		case elliptic.P256():
			curve = tpm2.CurveNISTP256
			hashAlg = tpm2.AlgSHA256
		case elliptic.P384():
			curve = tpm2.CurveNISTP384
			hashAlg = tpm2.AlgSHA384
		case elliptic.P521():
			curve = tpm2.CurveNISTP521
			hashAlg = tpm2.AlgSHA512

		default:
			return fmt.Errorf("unsupported curve parameter: %d", ek.Curve)
		}
		p := tpm2.Public{
			Type:       tpm2.AlgECC,
			NameAlg:    hashAlg,
			Attributes: tpm2.FlagSign | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth,
			ECCParameters: &tpm2.ECCParams{
				Sign: &tpm2.SigScheme{
					Alg:  tpm2.AlgECDSA,
					Hash: hashAlg,
				},
				CurveID: curve,
				Point:   tpm2.ECPoint{XRaw: ek.X.Bytes(), YRaw: ek.Y.Bytes()},
			},
		}
		pk, err := p.Encode()
		if err != nil {
			return fmt.Errorf("unable to encode a public key: %w", err)
		}
		k.PubArea = &pk
	default:
		return fmt.Errorf("unknown algorithm: %d", alg)
	}

	return nil
}

func (k *KAT) EncodeCertInfo(nonce []byte) error {
	ad := tpm2.AttestationData{}
	setTpmAttestDefaults(&ad)
	ad.Magic = TpmMagic
	ad.Type = tpm2.TagAttestCertify
	ad.ExtraData = nonce

	if k.PubArea == nil {
		return errors.New("cannot encode certInfo, as Pub Area is nil")
	}
	// Get the parameters of CerInfo from PubArea
	pub, err := tpm2.DecodePublic(*k.PubArea)
	if err != nil {
		return fmt.Errorf("unable to get algorithm from public area: %w", err)
	}

	alg := pub.NameAlg
	data, err := computeHash(alg, *k.PubArea)
	if err != nil {
		return fmt.Errorf("unable to compute hash %w", err)
	}

	ad.AttestedCertifyInfo = &tpm2.CertifyInfo{
		Name: tpm2.Name{
			Digest: &tpm2.HashValue{
				Alg:   alg,
				Value: data,
			},
		},
	}

	encoded, err := ad.Encode()
	if err != nil {
		return fmt.Errorf("unable to encode certify information: %w", err)
	}
	k.CertInfo = &encoded
	return nil
}

func (k KAT) validateCertAndPub() error {

	cert, err := k.DecodeCertInfo()
	if err != nil {
		return fmt.Errorf("invalid certificate information: %w", err)
	}

	if k.PubArea == nil {
		return errors.New("missing public key information")
	}
	pub, err := tpm2.DecodePublic(*k.PubArea)
	if err != nil {
		return fmt.Errorf("unable to decode the Public Area: %w", err)
	}
	if pub.Type != tpm2.AlgECC {
		return fmt.Errorf("invalid public key type: %d", pub.Type)
	}
	ha := swidHashAlgToTPMAlg(cert.Name.HashAlgID)
	if ha == tpm2.AlgUnknown {
		return fmt.Errorf("unable to map algorithm: %d", cert.Name.HashAlgID)
	}

	if pub.NameAlg != ha {
		return fmt.Errorf("hash alg mismatch cert info alg: = %d, pub area alg: =%d", pub.NameAlg, ha)
	}

	data, err := computeHash(ha, *k.PubArea)
	if err != nil {
		return fmt.Errorf("unable to compute hash: %w", err)
	}

	if !reflect.DeepEqual(data, cert.Name.Digest) {
		return errors.New("match failed")
	}

	return nil
}
