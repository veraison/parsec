// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package parsectpm

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"

	tpm2 "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/veraison/eat"
	cose "github.com/veraison/go-cose"
)

type KAT struct {
	TpmVer   *string `cbor:"tpmVer" json:"tpmVer"`
	KID      *[]byte `cbor:"kid" json:"kid"`
	Alg      *int    `cbor:"alg" json:"alg"`
	Sig      *[]byte `cbor:"sig" json:"sig"`
	PubArea  *[]byte `cbor:"pubArea" json:"pubArea"`
	CertInfo *[]byte `cbor:"certInfo" json:"certInfo"`
}

func NewKAT() *KAT {
	return &KAT{}
}

func (k *KAT) SetTpmVer(v string) error {
	if v == "" {
		return fmt.Errorf("empty string specified")
	}
	k.TpmVer = &v
	return nil
}

func (k *KAT) SetKeyID(v []byte) error {
	data := eat.UEID(v)
	if err := data.Validate(); err != nil {
		return fmt.Errorf("failed to validate UEID: %w", err)
	}

	k.KID = &v
	return nil
}

func (k *KAT) SetAlg(v uint64) error {
	if alg := swidHashAlgToTPMAlg(v); alg != 0 {
		alg1 := int(alg)
		k.Alg = &(alg1)
		return nil
	} else {
		return fmt.Errorf("unable to set valid algorithm")
	}
}

func (k *KAT) SetSig(s []byte) error {
	k.Sig = &s
	return nil
}

func (k KAT) Validate() error {
	if k.TpmVer == nil {
		return fmt.Errorf("TPM Version not set")
	} else if *k.TpmVer == "" {
		return fmt.Errorf("Empty TPM Version")
	}

	if k.KID == nil {
		return fmt.Errorf("missing key identifier")
	}
	if err := validateKID(*k.KID); err != nil {
		return fmt.Errorf("invalid KID : %w", err)
	}

	if k.CertInfo == nil {
		return fmt.Errorf("no certificate information")
	}
	_, err := tpm2.DecodeAttestationData(*k.CertInfo)
	if err != nil {
		return fmt.Errorf("failed to decode supplied certification information %w", err)
	}

	if k.Sig == nil {
		return fmt.Errorf("missing signature")
	}
	// Check the signature decode results in a success or not?
	_, err = tpm2.DecodeSignature(bytes.NewBuffer(*k.Sig))
	if err != nil {
		return fmt.Errorf("not a valid signature")
	}

	if k.PubArea == nil {
		return fmt.Errorf("missing public key information")
	}
	_, err = tpm2.DecodePublic(*k.PubArea)
	if err != nil {
		return fmt.Errorf("unable to decode the Public Area %w", err)
	}
	return nil
}

type DigestInfo struct {
	HashAlgID uint64
	Digest    []byte
}

type NameInfo struct {
	Handle  uint32
	DigInfo DigestInfo
}

type TpmCertInfo struct {
	Name          NameInfo
	QualifiedName NameInfo
}

type CertInfo struct {
	Magic       uint32
	Type        uint16
	Nonce       []byte
	TpmCertInfo TpmCertInfo
}

func (k KAT) DecodeCertInfo() (*CertInfo, error) {
	certInfo := &CertInfo{}

	if k.CertInfo == nil {
		return nil, fmt.Errorf("no certification information to decode")
	}

	ad, err := tpm2.DecodeAttestationData(*k.CertInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to decode supplied attestation information %w", err)
	}

	if ad.AttestedCertifyInfo == nil {
		return nil, fmt.Errorf("no certify information in the TPMS Attest")
	}
	certInfo.Magic = ad.Magic
	certInfo.Type = uint16(ad.Type)
	certInfo.Nonce = ad.ExtraData

	nameInfo, err := getNameInfo(ad.AttestedCertifyInfo.Name)
	if err != nil {
		return nil, fmt.Errorf("unable to decode the Name field")
	}
	certInfo.TpmCertInfo.Name = *nameInfo

	qnameInfo, err := getNameInfo(ad.AttestedCertifyInfo.QualifiedName)
	if err != nil {
		return nil, fmt.Errorf("unable to decode the Qualified Name field")
	}
	certInfo.TpmCertInfo.Name = *qnameInfo

	return certInfo, nil
}

func getNameInfo(name tpm2.Name) (*NameInfo, error) {
	nameInfo := &NameInfo{}

	if name.Handle != nil {
		nameInfo.Handle = uint32(*name.Handle)
	}

	alg := tpmHashAlgToSWIDHash(name.Digest.Alg)
	if alg == 0 {
		return nil, fmt.Errorf("unable to get the algorithm identity")
	}
	nameInfo.DigInfo.HashAlgID = alg
	nameInfo.DigInfo.Digest = name.Digest.Value

	return nameInfo, nil
}

// DecodePubArea decodes a given public key, from TPMT_PUBLIC structure
func (k KAT) DecodePubArea() (crypto.PublicKey, error) {

	if k.PubArea == nil {
		return nil, fmt.Errorf("no public key parameters to decode")
	}
	pub, err := tpm2.DecodePublic(*k.PubArea)
	if err != nil {
		return nil, fmt.Errorf("unable to decode the Public Area %w", err)
	}
	pk, err := pub.Key()
	if err != nil {
		return nil, fmt.Errorf("unable to get crypto public key from TPM2 public key %w", err)
	}
	return pk, nil
}

// Verify verifies the signature on the given key attestation token
// using supplied Public Key
func (k KAT) Verify(key crypto.PublicKey) error {

	if k.CertInfo == nil || len(*k.CertInfo) == 0 {
		return fmt.Errorf("no payload content to verify")
	}

	if k.Sig == nil || len(*k.Sig) == 0 {
		return fmt.Errorf("no signature on the key attestation token")
	}
	err := verify(key, *k.CertInfo, *k.Sig)
	if err != nil {
		return fmt.Errorf("failed to verify signature %w", err)
	}
	return nil
}

func (k *KAT) EncodePubArea(alg cose.Algorithm, key crypto.PublicKey) error {

	switch alg {
	case cose.AlgorithmES256, cose.AlgorithmES384, cose.AlgorithmES512:
		ek, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("invalid ECDSA public key ")
		}

		if !ek.Curve.IsOnCurve(ek.X, ek.Y) {
			return fmt.Errorf("public key is not on the curve")
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
			return fmt.Errorf("unsupported curve paramter %d", ek.Curve)
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
			return fmt.Errorf("unable to encode a public key")
		}
		k.PubArea = &pk
	case cose.AlgorithmPS256, cose.AlgorithmPS384, cose.AlgorithmPS512:
		rk, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("invalid RSA public key ")
		}

		p := tpm2.Public{
			Type:       tpm2.AlgRSA,
			NameAlg:    tpm2.AlgSHA256,
			Attributes: tpm2.FlagSign | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth,
			RSAParameters: &tpm2.RSAParams{
				Sign: &tpm2.SigScheme{
					Alg:  tpm2.AlgRSASSA,
					Hash: tpm2.AlgSHA256,
				},
				KeyBits:     2048,
				ExponentRaw: uint32(rk.E),
				ModulusRaw:  rk.N.Bytes(),
			},
		}
		pk, err := p.Encode()
		if err != nil {
			return fmt.Errorf("unable to encode a public key")
		}
		k.PubArea = &pk
	}

	return nil
}

func (k *KAT) EncodeCertInfo(c CertInfo) error {
	ad := tpm2.AttestationData{}
	setTpmAttestDefaults(&ad)
	ad.Magic = c.Magic
	ad.Type = tpmutil.Tag(c.Type)
	ad.ExtraData = c.Nonce

	name := tpmutil.Handle(c.TpmCertInfo.Name.Handle)
	alg := swidHashAlgToTPMAlg(c.TpmCertInfo.Name.DigInfo.HashAlgID)
	if alg == 0 {
		return fmt.Errorf("unable to map algorithm")
	}
	cName := tpmutil.Handle(c.TpmCertInfo.QualifiedName.Handle)
	cAlg := swidHashAlgToTPMAlg(c.TpmCertInfo.QualifiedName.DigInfo.HashAlgID)
	if cAlg == 0 {
		return fmt.Errorf("unable to map algorithm")
	}

	ad.AttestedCertifyInfo = &tpm2.CertifyInfo{
		Name: tpm2.Name{
			Handle: &name,
			Digest: &tpm2.HashValue{
				Alg:   alg,
				Value: c.TpmCertInfo.Name.DigInfo.Digest,
			},
		},
		QualifiedName: tpm2.Name{
			Handle: &cName,
			Digest: &tpm2.HashValue{
				Alg:   cAlg,
				Value: c.TpmCertInfo.QualifiedName.DigInfo.Digest,
			},
		},
	}

	encoded, err := ad.Encode()
	if err != nil {
		return fmt.Errorf("unable to encode certify information")
	}
	k.CertInfo = &encoded
	return nil
}
