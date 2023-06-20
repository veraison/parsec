# Parsec TPM Key Attestation Format

The `parsec/tpm` package provides the following features:

* Encode a Parsec TPM Evidence, containing a Key Attestation and Platform Attestation 
evidence and metadata to CBOR and JSON formats

* Decode a CBOR and JSON formatted Parsec TPM Evidence

* Verify the signature on the Key and Platform Attestation data using the supplied public key

* Sign the input Key and/or Platform Attestation data using the supplied private key
