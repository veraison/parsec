# parsec-tpm

A Library to Encode and Decode Parsec TPM Evidence as
detailed in [attested-tls-poc](github.com/CCC-Attestation/attested-tls-poc)

It provides following features

* Encode a Parsec TPM Evidence Collection, containing a Key Attestation and Platform Attestation 
information to CBOR and JSON formats

* Decode a CBOR and JSON formatted Parsec TPM Evidence into a Parsec TPM Evidence Collection

* Verify the signature on the Key and Platform Attestation elements using the supplied public key

* Sign the Supplied Key and/or Platform Attestation elements using the supplied key