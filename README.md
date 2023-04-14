# parsec-tpm

A Library to handle Parsec TPM Evidence as
detailed in [attested-tls-poc](https://github.com/CCC-Attestation/attested-tls-poc)

It provides following features

* Encode a Parsec TPM Evidence, containing a Key Attestation and Platform Attestation 
evidence and metadata to CBOR and JSON formats

* Decode a CBOR and JSON formatted Parsec TPM Evidence

* Verify the signature on the Key and Platform Attestation data using the supplied public key

* Sign the input Key and/or Platform Attestation data using the supplied private key