package keystore

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

	keyId := privateKey.PublicData().ID()

	return &LocalPrivateKeyHandle{ privateKey: privateKey, keyId: keyId, keyType: keyType }, nil
}

func (m *MemoryKeysManager) SavePrivateKey(keyRole string, privateKey *PrivateKey) error {
	handles := m.keys[keyRole]
	handles = append(handles,
		&LocalPrivateKeyHandle{
			keyId:      privateKey.PublicData().ID(),
			keyType:    privateKey.Type,
			privateKey: privateKey,
		},
	)

	m.keys[keyRole] = handles
	return nil
}