# Parsec CCA Key Attestation Format

The `parsec/cca` package provides following features:

* Decode and validate a CBOR-encoded [Parsec CCA Key Attestation](https://github.com/CCC-Attestation/attested-tls-poc/blob/main/doc/parsec-evidence-cca.md) buffer;
* Verify the CCA token using the supplied CPAK public key;
* Verify the binding between the key and platform tokens;
* Provide access to all the claims in both the key and platform tokens.
