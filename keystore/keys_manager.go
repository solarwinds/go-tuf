package keystore

import "github.com/flynn/go-tuf/data"

type KeysManager interface
{
	// GenerateKey creates a new key of given type for given role
	GenerateKey(keyRole string, keyType string) (PrivateKeyHandle, error)

	// Imports an existing key from the key manager
	ImportKey(id string) (PrivateKeyHandle, error)
}

type PrivateKeyHandle interface {
	GetPublicKey() (*data.Key, error)
}

const (
	KeysManagerIdLocal = "local"
	KeysMangerIdKms    = "kms"
)



