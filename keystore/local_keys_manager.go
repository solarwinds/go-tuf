package keystore

import (
	"encoding/json"
	"fmt"
	"github.com/flynn/go-tuf/data"
	"github.com/flynn/go-tuf/encrypted"
	"github.com/flynn/go-tuf/util"
	"io/ioutil"
	"os"
	"path/filepath"
)

var _ KeysManager = &LocalKeysManager{}
type LocalKeysManager struct
{
	dir            string

	passphraseFunc util.PassphraseFunc

	// keys is a cache of persisted keys to avoid decrypting multiple times
	keys map[string /*role*/][]PrivateKeyHandle
}

var _ PrivateKeyHandle = &LocalPrivateKeyHandle{}
type LocalPrivateKeyHandle struct
{
	keyId      string
	keyType    string
	privateKey *PrivateKey
}

type persistedKeys struct {
	Encrypted bool            `json:"encrypted"`
	Data      json.RawMessage `json:"data"`
}

type ErrPassphraseRequired struct {
	Role string
}

func (e ErrPassphraseRequired) Error() string {
	return fmt.Sprintf("tuf: a passphrase is required to access the encrypted %s keys file", e.Role)
}

func NewLocalKeysManager(dir string, passphraseFunc util.PassphraseFunc) *LocalKeysManager {
	return &LocalKeysManager{
		dir:            dir,
		passphraseFunc: passphraseFunc,
		keys:        make(map[string][]PrivateKeyHandle),
	}
}

func (m *LocalKeysManager) ImportKey(keyRole string, externalKeyId string) (PrivateKeyHandle, error) {
	return nil, fmt.Errorf("local key manager does not support key import, use gen-key instead")
}

func (m *LocalKeysManager) GetPrivateKeyHandles(keyRole string) ([]PrivateKeyHandle, error) {
	if keys, ok := m.keys[keyRole]; ok {
		return keys, nil
	}
	privateKeys, _, err := m.loadPrivateKeys(keyRole)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	handles := m.createPrivateKeyHandles(privateKeys)
	m.keys[keyRole] = handles

	return handles, nil
}

func (m *LocalKeysManager) GenerateKey(keyRole string, keyType string) (PrivateKeyHandle, error) {
	privateKeyHandle, err := GenerateKey(keyType)
	if err != nil {
		return nil, err
	}

	if err := m.SavePrivateKey(keyRole, privateKeyHandle); err != nil {
		return nil, err
	}

	keyId := privateKeyHandle.PublicData().ID()

	return &LocalPrivateKeyHandle{ privateKey: privateKeyHandle, keyId: keyId, keyType: keyType }, nil
}

func (m *LocalKeysManager) SavePrivateKey(keyRole string, privateKey *PrivateKey) error {
	if err := m.createDirs(); err != nil {
		return err
	}

	// add the key to the existing keys (if any)
	privateKeys, pass, err := m.loadPrivateKeys(keyRole)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	privateKeys = append(privateKeys, privateKey)

	// if loadPrivateKeys didn't return a passphrase (because no keys yet exist)
	// and passphraseFunc is set, get the passphrase so the keys file can
	// be encrypted later (passphraseFunc being nil indicates the keys file
	// should not be encrypted)
	if pass == nil && m.passphraseFunc != nil {
		pass, err = m.passphraseFunc(keyRole, true)
		if err != nil {
			return err
		}
	}

	m.savePrivateKeys(privateKeys, pass, keyRole)

	handles := m.createPrivateKeyHandles(privateKeys)
	m.keys[keyRole] = handles

	return nil
}

func (m *LocalKeysManager) createPrivateKeyHandles(privateKeys []*PrivateKey) []PrivateKeyHandle {
	var handles []PrivateKeyHandle
	for _, k := range privateKeys {
		h := &LocalPrivateKeyHandle{
			keyId:      k.PublicData().ID(),
			keyType:    k.Type,
			privateKey: k,
		}
		handles = append(handles, h)
	}
	return handles
}

// loadPrivateKeys loads keys for the given role and returns them along with the
// passphrase (if read) so that callers don't need to re-read it.
func (m *LocalKeysManager) loadPrivateKeys(role string) ([]*PrivateKey, []byte, error) {
	file, err := os.Open(m.keysPath(role))
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	pk := &persistedKeys{}
	if err := json.NewDecoder(file).Decode(pk); err != nil {
		return nil, nil, err
	}

	var privateKeys []*PrivateKey
	var pass []byte
	if !pk.Encrypted {
		if err := json.Unmarshal(pk.Data, &privateKeys); err != nil {
			return nil, nil, err
		}

	} else {
		// the keys are encrypted so cannot be loaded if passphraseFunc is not set
		if m.passphraseFunc == nil {
			return nil, nil, ErrPassphraseRequired{role}
		}

		pass, err = m.passphraseFunc(role, false)
		if err != nil {
			return nil, nil, err
		}
		if err := encrypted.Unmarshal(pk.Data, &privateKeys, pass); err != nil {
			return nil, nil, err
		}
	}

	return privateKeys, pass, nil
}

func (m *LocalKeysManager) savePrivateKeys(privateKeys []*PrivateKey, pass []byte, keyRole string) error {
	pk := &persistedKeys{}
	var err error
	if pass != nil {
		pk.Data, err = encrypted.Marshal(privateKeys, pass)
		if err != nil {
			return err
		}
		pk.Encrypted = true
	} else {
		pk.Data, err = json.MarshalIndent(privateKeys, "", "\t")
		if err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(pk, "", "\t")
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(m.keysPath(keyRole), append(data, '\n'), 0600); err != nil {
		return err
	}
	return nil
}

func (m *LocalKeysManager) keysPath(role string) string {
	return filepath.Join(m.dir, "keys", role+".json")
}

func (m *LocalKeysManager) createDirs() error {
	for _, dir := range []string{"keys"} {
		if err := os.MkdirAll(filepath.Join(m.dir, dir), 0755); err != nil {
			return err
		}
	}
	return nil
}



func (l *LocalPrivateKeyHandle) GetPublicKey() (*data.Key, error) {
	return l.privateKey.PublicData(), nil
}

func (l *LocalPrivateKeyHandle) ID() string {
	return l.keyId
}

func (l *LocalPrivateKeyHandle) Type() string {
	return l.keyType
}

func (l *LocalPrivateKeyHandle) GetSigner() (Signer, error) {
	return l.privateKey.Signer(), nil
}