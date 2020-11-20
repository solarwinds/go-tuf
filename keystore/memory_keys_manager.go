package keystore

import "fmt"

var _ KeysManager = &MemoryKeysManager{}
type MemoryKeysManager struct
{
	// keys is a cache of persisted keys to avoid decrypting multiple times
	keys map[string /*role*/][]PrivateKeyHandle
}

func NewMemoryKeysManager() *MemoryKeysManager {
	return &MemoryKeysManager{
		keys: make(map[string][]PrivateKeyHandle),
	}
}

func (m *MemoryKeysManager) ImportKey(keyRole string, externalKeyId string) (PrivateKeyHandle, error) {
	panic("MemoryKeysManager does not support keys importing")
}

func (m *MemoryKeysManager) GetPrivateKeyHandles(keyRole string) ([]PrivateKeyHandle, error) {
	return m.keys[keyRole], nil
}

func (m *MemoryKeysManager) GenerateKey(keyRole string, keyType string) (PrivateKeyHandle, error) {
	privateKey, err := GenerateKey(keyType)
	if err != nil {
		return nil, err
	}

	if err := m.SavePrivateKey(keyRole, privateKey); err != nil {
		return nil, err
	}

	return privateKey, nil
}

func (m *MemoryKeysManager) AddKey(keyRole string, privateKey PrivateKeyHandle) error {
	pk, isPrivateKey := privateKey.(*PrivateKey)
	if !isPrivateKey {
		return fmt.Errorf("cannot add private key, only keys of type keystore.PrivateKey can be added")
	}
	return m.SavePrivateKey(keyRole, pk)
}

func (m *MemoryKeysManager) SavePrivateKey(keyRole string, privateKey *PrivateKey) error {
	handles := m.keys[keyRole]
	handles = append(handles,privateKey)

	m.keys[keyRole] = handles
	return nil
}