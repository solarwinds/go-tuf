package keystore

import "github.com/flynn/go-tuf/data"

type KeysManager interface
{
	GenerateKey(keyRole string, keyType string) (PrivateKeyHandle, error)
}

type PrivateKeyHandle interface {
	GetPublicKey() (*data.Key, error)
}

const (
	KeysManagerIdLocal = "local"
	KeysMangerIdKms    = "kms"
)



