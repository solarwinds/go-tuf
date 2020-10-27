package keystore

import (
	"github.com/flynn/go-tuf/data"
)

type KeysManager interface
{
	GenerateKey(keyRole string, keyType string) (PrivateKeyHandle, error)
}

type PrivateKeyHandle interface {
	GetPublicData() PublicDataHandle
}

// TODO: revisit, possibly not needed
type PublicDataHandle interface {
	ID() string
	GetKey() *data.Key
}

const (
	KeysManagerIdLocal = "local"
	KeysMangerIdKms    = "kms"
)



