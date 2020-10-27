package keystore

import (
	"encoding/json"
	"fmt"
	"github.com/flynn/go-tuf/data"
	"github.com/flynn/go-tuf/encrypted"
	"github.com/flynn/go-tuf/sign"
	"github.com/flynn/go-tuf/util"
	"io/ioutil"
	"os"
	"path/filepath"
)

type LocalKeysManager struct // implements KeysManager
{
	dir            string

	passphraseFunc util.PassphraseFunc

	// signers is a cache of persisted keys to avoid decrypting multiple times
	signers map[string][]sign.Signer
}

type LocalPrivateKeyHandle struct // implements PrivateKeyHandle
{
	privateKey *sign.PrivateKey
}

type LocalPublicDataHandle struct //  implements PublicDataHandle
{
	publicData *data.Key
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
		signers:        make(map[string][]sign.Signer),
	}
}

func (m *LocalKeysManager) GenerateKey(keyRole string, keyType string) (PrivateKeyHandle, error) {
	privateKey, err := sign.GenerateKey(keyType)
	if err != nil {
		return nil, err
	}

	if err := m.SavePrivateKey(keyRole, privateKey); err != nil {
		return nil, err
	}

	return &LocalPrivateKeyHandle{ privateKey: privateKey }, nil
}


func (m *LocalKeysManager) SavePrivateKey(role string, key *sign.PrivateKey) error {
	if err := m.createDirs(); err != nil {
		return err
	}

	// add the key to the existing keys (if any)
	keys, pass, err := m.loadKeys(role)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	keys = append(keys, key)

	// if loadKeys didn't return a passphrase (because no keys yet exist)
	// and passphraseFunc is set, get the passphrase so the keys file can
	// be encrypted later (passphraseFunc being nil indicates the keys file
	// should not be encrypted)
	if pass == nil && m.passphraseFunc != nil {
		pass, err = m.passphraseFunc(role, true)
		if err != nil {
			return err
		}
	}

	pk := &persistedKeys{}
	if pass != nil {
		pk.Data, err = encrypted.Marshal(keys, pass)
		if err != nil {
			return err
		}
		pk.Encrypted = true
	} else {
		pk.Data, err = json.MarshalIndent(keys, "", "\t")
		if err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(pk, "", "\t")
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(m.keysPath(role), append(data, '\n'), 0600); err != nil {
		return err
	}
	m.signers[role] = m.privateKeySigners(keys)
	return nil
}


func (m *LocalKeysManager) GetSigningKeys(role string) ([]sign.Signer, error) {
	if keys, ok := m.signers[role]; ok {
		return keys, nil
	}
	keys, _, err := m.loadKeys(role)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	m.signers[role] = m.privateKeySigners(keys)
	return m.signers[role], nil
}


func (m *LocalKeysManager) privateKeySigners(keys []*sign.PrivateKey) []sign.Signer {
	res := make([]sign.Signer, len(keys))
	for i, k := range keys {
		res[i] = k.Signer()
	}
	return res
}

// loadKeys loads keys for the given role and returns them along with the
// passphrase (if read) so that callers don't need to re-read it.
func (m *LocalKeysManager) loadKeys(role string) ([]*sign.PrivateKey, []byte, error) {
	file, err := os.Open(m.keysPath(role))
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	pk := &persistedKeys{}
	if err := json.NewDecoder(file).Decode(pk); err != nil {
		return nil, nil, err
	}

	var keys []*sign.PrivateKey
	if !pk.Encrypted {
		if err := json.Unmarshal(pk.Data, &keys); err != nil {
			return nil, nil, err
		}
		return keys, nil, nil
	}

	// the keys are encrypted so cannot be loaded if passphraseFunc is not set
	if m.passphraseFunc == nil {
		return nil, nil, ErrPassphraseRequired{role}
	}

	pass, err := m.passphraseFunc(role, false)
	if err != nil {
		return nil, nil, err
	}
	if err := encrypted.Unmarshal(pk.Data, &keys, pass); err != nil {
		return nil, nil, err
	}
	return keys, pass, nil
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

func (l LocalPublicDataHandle) ID() string {
	return l.publicData.ID()
}

func (l LocalPublicDataHandle) GetKey() *data.Key {
	return l.publicData
}

func (l LocalPrivateKeyHandle) GetPublicData() PublicDataHandle {
	return &LocalPublicDataHandle{
		publicData: l.privateKey.PublicData(),
	}
}