package sign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"log"
	"sync"

	"github.com/flynn/go-tuf/data"
	"golang.org/x/crypto/ed25519"
)

type PrivateKey struct {
	Type  string          `json:"keytype"`
	Value PrivateKeyValue `json:"keyval"`
}

type PrivateKeyValue struct {
	Public  data.HexBytes `json:"public"`
	Private data.HexBytes `json:"private"`
}

func (k *PrivateKey) PublicData() *data.Key {
	return &data.Key{
		Type:  k.Type,
		Value: data.KeyValue{Public: k.Value.Public},
	}
}

func (k *PrivateKey) Signer() Signer {
	if k.Type == data.KeyTypeEd25519 {
		return &ed25519Signer{PrivateKey: ed25519.PrivateKey(k.Value.Private)}
	} else if k.Type == data.KeyTypeECDSA_SHA2_P256 {
		privateKey, err := x509.ParseECPrivateKey(k.Value.Private)
		if err != nil {
			log.Printf("Failed to parse ecdsa private key")
			return nil
		}

		return &ecdsaSigner{PrivateKey: *privateKey}
	} else {
		log.Printf("Unsupported key type %s. Cannot prepare signer.", k.Type)
		return nil
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

type ed25519Signer struct {
	ed25519.PrivateKey

	id     string
	idOnce sync.Once
}

var _ Signer = &ed25519Signer{}

func (s *ed25519Signer) ID() string {
	s.idOnce.Do(func() { s.id = s.publicData().ID() })
	return s.id
}

func (s *ed25519Signer) publicData() *data.Key {
	return &data.Key{
		Type:  data.KeyTypeEd25519,
		Value: data.KeyValue{Public: []byte(s.PrivateKey.Public().(ed25519.PublicKey))},
	}
}

func (s *ed25519Signer) Type() string {
	return data.KeyTypeEd25519
}

type ecdsaSigner struct {
	ecdsa.PrivateKey

	id     string
	idOnce sync.Once
}

var _ Signer = &ecdsaSigner{}

func (s *ecdsaSigner) ID() string {
	s.idOnce.Do(func() { s.id = s.publicData().ID() })
	return s.id
}

func (s *ecdsaSigner) publicData() *data.Key {
	publicKey := s.PrivateKey.Public().(*ecdsa.PublicKey)

	x509PublicKey, _ := x509.MarshalPKIXPublicKey(publicKey)

	return &data.Key{
		Type:  data.KeyTypeECDSA_SHA2_P256,
		Value: data.KeyValue{Public: x509PublicKey},
	}
}

func (s *ecdsaSigner) Type() string {
	return data.KeyTypeECDSA_SHA2_P256
}
