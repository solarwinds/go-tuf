package keystore

type Signer interface {
	// Signer is used to sign messages and provides access to the public key.
	// The signer is expected to do its own hashing, so the full message will be
	// provided as the message to Sign with a zero opts.HashFunc().
	Sign(data []byte) ([]byte, error)
}


