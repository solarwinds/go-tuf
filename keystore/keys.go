package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"github.com/theupdateframework/go-tuf/data"
	"golang.org/x/crypto/ed25519"
	"sync"
)

var _ PrivateKeyHandle = &PrivateKey{}
type PrivateKey struct {
	Type       string          `json:"keytype"`
	Scheme     string          `json:"scheme,omitempty"`
	Algorithms []string        `json:"keyid_hash_algorithms,omitempty"`
	Value      PrivateKeyValue `json:"keyval"`

	publicKey     *data.Key    `json:"-"`
	publicKeyOnce sync.Once    `json:"-"`
}


func (k *PrivateKey) GetIDs() []string {
	publicKey, err := k.GetPublicKey()
	if err != nil {
		return []string{}
	}
	return publicKey.IDs()
}

func (k *PrivateKey) ContainsKeyID(keyId string) bool {
	publicKey, err := k.GetPublicKey()
	if err != nil {
		return false
	}
	return publicKey.ContainsID(keyId)
}


func (k *PrivateKey) GetType() string {
	return k.Type
}

type PrivateKeyValue struct {
	Public  data.HexBytes `json:"public"`
	Private data.HexBytes `json:"private"`
}

func (k *PrivateKey) GetPublicKey() (*data.Key, error) {
	k.publicKeyOnce.Do(func() {
		k.publicKey = &data.Key{
			Type:       k.Type,
			Scheme:     k.Scheme,
			Algorithms: k.Algorithms,
			Value:      data.KeyValue{Public: k.Value.Public},
		}
	})
	if k.publicKey != nil {
		return k.publicKey, nil
	} else {
		return nil, fmt.Errorf("failed to initialize public key")
	}
}

func (k *PrivateKey) GetSigner() (Signer, error) {
	if k.Type == data.KeyTypeEd25519 {
		return &ed25519Signer{
			privateKey:    ed25519.PrivateKey(k.Value.Private),
			keyType:       k.Type,
			keyScheme:     k.Scheme,
			keyAlgorithms: k.Algorithms,
		}, nil
	} else if k.Type == data.KeyTypeECDSA_SHA2_P256 {
		privateKey, err := x509.ParseECPrivateKey(k.Value.Private)
		if err != nil {
			return nil, err
		}

		return &ecdsaSigner{privateKey: *privateKey}, nil
	} else {
		return nil, fmt.Errorf("unsupported key type %s, cannot prepare signer", k.Type)
	}
}

func GenerateKey(keyType string) (*PrivateKey, error) {
	if keyType == data.KeyTypeEd25519 {
		return GenerateEd25519Key()
	} else if keyType == data.KeyTypeECDSA_SHA2_P256 {
		return GenerateEcdsaP256Key()
	} else {
		return nil, fmt.Errorf("Unsupported key type %s. Use either %s (default) or %s", keyType, data.KeyTypeEd25519, data.KeyTypeECDSA_SHA2_P256)
	}
}

func GenerateEd25519Key() (*PrivateKey, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{
		Type: data.KeyTypeEd25519,
		Value: PrivateKeyValue{
			Public:  data.HexBytes(public),
			Private: data.HexBytes(private),
		},
	}, nil
}

func GenerateEcdsaP256Key() (*PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	publicKey := privateKey.Public().(*ecdsa.PublicKey)

	x509PublicKey, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	x509PrivateKey, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{
		Type: data.KeyTypeECDSA_SHA2_P256,
		Value: PrivateKeyValue{
			Public:  data.HexBytes(x509PublicKey),
			Private: data.HexBytes(x509PrivateKey),
		},
	}, nil
}

type ed25519Signer struct {
	privateKey ed25519.PrivateKey

	keyType       string
	keyScheme     string
	keyAlgorithms []string
	ids           []string
	idOnce        sync.Once
}

var _ Signer = &ed25519Signer{}

func (s *ed25519Signer) IDs() []string {
	s.idOnce.Do(func() { s.ids = s.publicData().IDs() })
	return s.ids
}

func (s *ed25519Signer) Sign(data []byte) ([]byte, error) {
	return s.privateKey.Sign(rand.Reader, data, crypto.Hash(0))
}

func (s *ed25519Signer) publicData() *data.Key {
	return &data.Key{
		Type:       s.keyType,
		Scheme:     s.keyScheme,
		Algorithms: s.keyAlgorithms,
		Value:      data.KeyValue{Public: []byte(s.privateKey.Public().(ed25519.PublicKey))},
	}
}

func (s *ed25519Signer) Type() string {
	return s.keyType
}

func (s *ed25519Signer) Scheme() string {
	return s.keyScheme
}


type ecdsaSigner struct {
	privateKey ecdsa.PrivateKey
}

func (s *ecdsaSigner) Sign(data []byte) ([]byte, error) {
	return s.privateKey.Sign(rand.Reader, data, crypto.Hash(0))
}

var _ Signer = &ecdsaSigner{}

func (s *ecdsaSigner) publicData() *data.Key {
	publicKey := s.privateKey.Public().(*ecdsa.PublicKey)

	x509PublicKey, _ := x509.MarshalPKIXPublicKey(publicKey)

	return &data.Key{
		Type:  data.KeyTypeECDSA_SHA2_P256,
		Value: data.KeyValue{Public: x509PublicKey},
	}
}