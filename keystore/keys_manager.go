package keystore

import "github.com/theupdateframework/go-tuf/data"

type KeysManager interface
{
	// GenerateKey creates a new key of given type for given role
	GenerateKey(keyRole string, keyType string) (PrivateKeyHandle, error)

	// Imports an existing key from the key manager.
	// E.g. allows to import key from KMS
	ImportKey(keyRole string, externalKeyId string) (PrivateKeyHandle, error)

	// Returns all keys for given role
	GetPrivateKeyHandles(keyRole string) ([]PrivateKeyHandle, error)

	// Adds given key to the manager. Allows to add a key generated elsewhere.
	AddKey(keyRole string, key PrivateKeyHandle) error
}

type PrivateKeyHandle interface {
	GetIDs() []string
	ContainsKeyID(keyId string) bool
	GetType() string
	GetScheme() string
	GetAlgorithms() []string
	GetPublicKey() (*data.Key, error)
	GetSigner() (Signer, error)
}

const (
	KeysManagerIdLocal = "local"
	KeysMangerIdKms    = "kms"
)



