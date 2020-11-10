package keystore

import "github.com/flynn/go-tuf/data"

type KeysManager interface
{
	// GenerateKey creates a new key of given type for given role
	GenerateKey(keyRole string, keyType string) (PrivateKeyHandle, error)

	// Imports an existing key from the key manager
	ImportKey(keyRole string, externalKeyId string) (PrivateKeyHandle, error)

	GetPrivateKeyHandles(keyRole string) ([]PrivateKeyHandle, error)

	//Sign()
}

type PrivateKeyHandle interface {
	ID() string
	Type() string
	GetPublicKey() (*data.Key, error)
	GetSigner() (Signer, error)
}

const (
	KeysManagerIdLocal = "local"
	KeysMangerIdKms    = "kms"
)



