package keystore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/theupdateframework/go-tuf/data"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
)

var _ KeysManager = &KmsKeysManager{}
type KmsKeysManager struct
{
	dir                string
	entries            []KmsKeyEntry
	entriesStorePath   string
	loadKeyEntriesOnce sync.Once

	initSessionOnce sync.Once
	session         *session.Session

	initKmsServiceOnce sync.Once
	kmsService         *kms.KMS

	initStsServiceOnce sync.Once
	stsService         *sts.STS
}

var _ PrivateKeyHandle = &KmsPrivateKeyHandle{}
type KmsPrivateKeyHandle struct
{
	keyIds 			 []string
	keyType          string
	kmsExternalKeyId string
	manager          *KmsKeysManager
}



var _ Signer  = &KmsSigner{}
type KmsSigner struct
{
	key     *KmsPrivateKeyHandle
}

type KmsKeyEntry struct {
	KeyRole      string `json:"role"`
	KeyType      string `json:"type"`
	Arn          string `json:"arn"`
	PublicKeyIds []string `json:"publicKeyIds"`
}

func (h *KmsPrivateKeyHandle) GetIDs() []string {
	return h.keyIds
}

func (h *KmsPrivateKeyHandle) ContainsKeyID(keyId string) bool {
	for _, id := range h.keyIds {
		if id == keyId {
			return true
		}
	}
	return false
}

func (h *KmsPrivateKeyHandle) GetType() string {
	return h.keyType
}

func (h *KmsPrivateKeyHandle) GetSigner() (Signer, error) {
	return &KmsSigner{key: h}, nil
}

func (h *KmsPrivateKeyHandle) GetPublicKey() (*data.Key, error) {

	kmsService := h.manager.getKmsService()

	input := &kms.GetPublicKeyInput{
		KeyId:       &h.kmsExternalKeyId,
	}

	output, err := kmsService.GetPublicKey(input)

	// output.PublicKey is DER-encoded X.509 public key also known as SubjectPublicKeyInfo (SPKI)
	publicKey, err := x509.ParsePKIXPublicKey(output.PublicKey)
	if err != nil {
		return nil, err
	}

	publicKeyEcdsa, isEcdsa := publicKey.(*ecdsa.PublicKey)
	if !isEcdsa {
		return nil, fmt.Errorf("expected ecdsa public key but received %s", reflect.TypeOf(publicKeyEcdsa))
	}

	// TODO: standard says: PUBLIC is in PEM format and a string.
	// so probably stright what comes from KMS, but this needs to be checked against the python impl
	// but this elliptic.Marshal matches what the verifier impl did previously
	bytes := elliptic.Marshal(publicKeyEcdsa.Curve, publicKeyEcdsa.X, publicKeyEcdsa.Y)

	if err != nil {
		return nil, err
	}
	key := &data.Key{
		Type:  h.keyType,
		Value: data.KeyValue{Public: bytes },
	}

	return key, nil
}

func NewKmsKeysManager(dir string) *KmsKeysManager {

	entriesStorePath := path.Join(dir, "kms", "kms.json")
	return &KmsKeysManager{dir: dir, entriesStorePath: entriesStorePath, entries: []KmsKeyEntry{}}
}

func (m *KmsKeysManager) getSession() *session.Session {

	m.initSessionOnce.Do(func() {
		m.session = session.Must(session.NewSession())
		// TODO: unhardcode region
		region := "us-west-2"
		m.session.Config.Region = &region
	})
	return m.session
}

func (m *KmsKeysManager)getKmsService() *kms.KMS {
	m.initKmsServiceOnce.Do(func() {
		m.kmsService = kms.New(m.getSession())
	})
	return m.kmsService
}

func (m *KmsKeysManager)getStsService() *sts.STS {
	m.initStsServiceOnce.Do(func() {
		m.stsService = sts.New(m.getSession())
	})
	return m.stsService
}

func (m *KmsKeysManager) GenerateKey(keyRole string, keyType string) (PrivateKeyHandle, error) {
	kmsService := m.getKmsService()
	stsService := m.getStsService()

	createKeyInput := &kms.CreateKeyInput{

		Description: aws.String("This is TUF key for " + keyRole + " role."),
		Tags: []*kms.Tag{
			{
				TagKey:   aws.String("Role"),
				TagValue: aws.String(keyRole),
			},
			{
				TagKey:   aws.String("Source"),
				TagValue: aws.String("TUF"),
			},
		},
	}

	var customerMasterKeySec string
	if keyType == data.KeyTypeECDSA_SHA2_P256 {
		customerMasterKeySec = kms.DataKeyPairSpecEccNistP256
	} else if keyType == data.KeyTypeRSASSA_PSS_SHA256 {
		customerMasterKeySec = kms.DataKeyPairSpecRsa2048
	} else if keyType == data.KeyTypeEd25519 {
		return nil, fmt.Errorf("KMS does not support keys of %s type, use either %s or %s", data.KeyTypeEd25519, data.KeyTypeECDSA_SHA2_P256, data.KeyTypeRSASSA_PSS_SHA256)
	} else {
		return nil, fmt.Errorf("unsupported type of key %s, use either %s or %s which are supported by KMS", keyType, data.KeyTypeECDSA_SHA2_P256, data.KeyTypeRSASSA_PSS_SHA256)
	}

	createKeyInput.CustomerMasterKeySpec = &customerMasterKeySec

	keyUsageTypeSignVerify := kms.KeyUsageTypeSignVerify
	createKeyInput.KeyUsage = &keyUsageTypeSignVerify

	callerIdentityInput := &sts.GetCallerIdentityInput{}
	callerIdentityOutput, err := stsService.GetCallerIdentity(callerIdentityInput)
	if err != nil { return nil, err }

	var policy = `{
   "Id": "custom-policy-2016-12-09",
   "Version": "2012-10-17",
   "Statement": [
       {
           "Sid": "Enable IAM User Permissions",
           "Effect": "Allow",
           "Principal": {
               "AWS": "arn:aws:iam::{ACCOUNT}:root"
           },
           "Action": "kms:*",
           "Resource": "*"
       },
       {
           "Sid": "Allow access for Key Administrators",
           "Effect": "Allow",
           "Principal": {
               "AWS": "{ARN}"
           },
           "Action": [
               "kms:Create*",
               "kms:Describe*",
               "kms:Enable*",
               "kms:List*",
               "kms:Put*",
               "kms:Update*",
               "kms:Revoke*",
               "kms:Disable*",
               "kms:Get*",
               "kms:Delete*",
               "kms:ScheduleKeyDeletion",
               "kms:CancelKeyDeletion"
           ],
           "Resource": "*"
       },
       {
           "Sid": "Allow use of the key",
           "Effect": "Allow",
           "Principal": {
               "AWS": "{ARN}"
           },
           "Action": [
               "kms:Encrypt",
               "kms:Decrypt",
               "kms:ReEncrypt*",
               "kms:GenerateDataKey*",
               "kms:DescribeKey"
           ],
           "Resource": "*"
       },
       {
           "Sid": "Allow attachment of persistent resources",
           "Effect": "Allow",
           "Principal": {
               "AWS": "{ARN}"
           },
           "Action": [
               "kms:CreateGrant",
               "kms:ListGrants",
               "kms:RevokeGrant"
           ],
           "Resource": "*",
           "Condition": {
               "Bool": {
                   "kms:GrantIsForAWSResource": "true"
               }
           }
       }
   ]
}
`

	replacer := strings.NewReplacer(
		"{ARN}", *callerIdentityOutput.Arn,
		"{ACCOUNT}", *callerIdentityOutput.Account,
	)
	policy = replacer.Replace(policy)
	createKeyInput.Policy = aws.String(policy)

	createKeyOutput, err := kmsService.CreateKey(createKeyInput)
	if err != nil { return nil, err }

	privateKeyHandle := &KmsPrivateKeyHandle{
		manager: m,
		kmsExternalKeyId: *createKeyOutput.KeyMetadata.KeyId,
		keyType: keyType,
	}

	publicKey, err := privateKeyHandle.GetPublicKey()
	if err != nil { return nil, err }

	ids := publicKey.IDs()
	privateKeyHandle.keyIds = ids

	alias := m.getAlias(publicKey)
	createInput := &kms.CreateAliasInput{
		AliasName:   aws.String("alias/" + alias),
		TargetKeyId: createKeyOutput.KeyMetadata.KeyId,
	}
	_, err = kmsService.CreateAlias(createInput)
	if err != nil { return nil, err }

	var tags []*kms.Tag
	for i, id := range ids {
		tags = append(tags, &kms.Tag{
				TagKey:   aws.String(fmt.Sprintf("TUF Key Id %d", i)),
				TagValue: aws.String(id),
			})
	}

	tagInput := &kms.TagResourceInput{
		KeyId: createKeyOutput.KeyMetadata.KeyId,
		Tags: tags,
	}
	_, err = kmsService.TagResource(tagInput)
	if err != nil { return nil, err }

	err = m.addKeyEntry(&KmsKeyEntry {
		KeyRole: keyRole,
		KeyType: keyType,
		Arn: *createKeyOutput.KeyMetadata.Arn,
		PublicKeyIds: ids,
	})
	if err != nil { return nil, err }

	return privateKeyHandle, nil
}

func (m *KmsKeysManager) ImportKey(keyRole string, externalKeyId string) (PrivateKeyHandle, error) {
	kmsService := m.getKmsService()

	describeKeyInput := &kms.DescribeKeyInput{
		KeyId: aws.String(externalKeyId),
	}

	describeKeyOutput, err := kmsService.DescribeKey(describeKeyInput)
	if err != nil { return nil, err }

	var keyType string
	spec := *describeKeyOutput.KeyMetadata.CustomerMasterKeySpec
	if spec == kms.CustomerMasterKeySpecRsa2048 {
		keyType = data.KeyTypeRSASSA_PSS_SHA256
	} else if spec == kms.CustomerMasterKeySpecEccNistP256 {
		keyType = data.KeyTypeECDSA_SHA2_P256
	} else {
		return nil, fmt.Errorf("failed to import the key from KMS, key spec %s is not supported, only key specs %s and %s are supported", spec,
			kms.CustomerMasterKeySpecRsa2048, kms.CustomerMasterKeySpecEccNistP256)
	}

	privateKeyHandle := &KmsPrivateKeyHandle{
		manager: m,
		kmsExternalKeyId: *describeKeyOutput.KeyMetadata.KeyId,
		keyType: keyType,
	}

	publicKey, err := privateKeyHandle.GetPublicKey()
	if err != nil { return nil, err }

	privateKeyHandle.keyIds = publicKey.IDs()

	err = m.addKeyEntry(&KmsKeyEntry	{
		KeyRole: keyRole,
		KeyType: keyType,
		Arn: *describeKeyOutput.KeyMetadata.Arn,
		PublicKeyIds:publicKey.IDs(),
	})
	if err != nil { return nil, err }

	return privateKeyHandle, nil
}


func (m *KmsKeysManager) GetPrivateKeyHandles(keyRole string) ([]PrivateKeyHandle, error) {
	err := m.initKeyEntries()

	if err != nil {
		return nil, err
	}
	var result []PrivateKeyHandle
	for _, entry := range m.entries {
		if entry.KeyRole == keyRole {
			handle := &KmsPrivateKeyHandle{
				keyIds:           entry.PublicKeyIds,
				keyType:          entry.KeyType,
				kmsExternalKeyId: entry.Arn,
				manager:          m,
			}
			result = append(result, handle)
		}
	}

	return result, nil
}

func (m *KmsKeysManager) createDirs() error {
	for _, dir := range []string{"kms"} {
		if err := os.MkdirAll(filepath.Join(m.dir, dir), 0755); err != nil {
			return err
		}
	}
	return nil
}

func (m *KmsKeysManager) initKeyEntries() error {
	var err error = nil
	m.loadKeyEntriesOnce.Do(func() {
		err = m.loadKeyEntries()
	})
	return err
}

func (m *KmsKeysManager) addKeyEntry(newEntry *KmsKeyEntry) error {
	err := m.initKeyEntries()

	if err != nil {
		return err
	}

	var newEntries []KmsKeyEntry

	for _, existingEntry := range m.entries {
		if m.noneKeyMatches(&existingEntry, newEntry) || existingEntry.KeyRole != newEntry.KeyRole {
			newEntries = append(newEntries, existingEntry)
		}
	}
	newEntries = append(newEntries, *newEntry)
	m.entries = newEntries

	return m.saveKeyEntries()
}

func (m *KmsKeysManager) noneKeyMatches(existingEntry *KmsKeyEntry, newEntry *KmsKeyEntry) bool {
	for _, existingEntryId := range existingEntry.PublicKeyIds {
		for _, newEntryId := range newEntry.PublicKeyIds {
			if existingEntryId == newEntryId {
				return false
			}
		}
	}
	return true
}

func (m *KmsKeysManager) saveKeyEntries() error {
	err := m.createDirs()
	if err != nil { return err }

	j, err := json.MarshalIndent(m.entries, "", "    ")
	if err != nil { return err }


	err = ioutil.WriteFile(m.entriesStorePath, j, 0644)
	if err != nil { return err}

	return nil
}

func (m *KmsKeysManager) loadKeyEntries() error {
	_, err := os.Stat(m.entriesStorePath)
	if os.IsNotExist(err) {
		return nil
	}

	j, err := ioutil.ReadFile(m.entriesStorePath)
	if err != nil { return err }

	err = json.Unmarshal(j, &m.entries)
	if err != nil  { return err }

	return nil
}

// getAlias returns an alias that is assigned to the key at KMS
// the alias consists of the first 8 characters of each id of the key
func (m *KmsKeysManager) getAlias(publicKey *data.Key) string {
	ids := publicKey.IDs()

	var short []string
	for _, id := range ids {
		short = append(short, id[0:8])
	}

	return "TUF_" + strings.Join(short, "_")
}

func (s *KmsSigner) Sign(bytes []byte) ([]byte, error) {
	kmsService := s.key.manager.getKmsService()

	var algorithm string
	var digest []byte
	if s.key.keyType == data.KeyTypeRSASSA_PSS_SHA256{
		algorithm = kms.SigningAlgorithmSpecRsassaPssSha256
		d := sha256.Sum256(bytes)
		digest = d[:]
	} else if s.key.keyType == data.KeyTypeECDSA_SHA2_P256 {
		algorithm = kms.SigningAlgorithmSpecEcdsaSha256
		d := sha256.Sum256(bytes)
		digest = d[:]
	} else {
		return nil, fmt.Errorf("cannot sign data, key type %s is not supported by KMS", s.key.keyType)
	}

	signInput := &kms.SignInput{
		KeyId:            aws.String(s.key.kmsExternalKeyId),
		Message:          digest,
		MessageType:      aws.String(kms.MessageTypeDigest),
		SigningAlgorithm: aws.String(algorithm),
	}

	signOutput, err := kmsService.Sign(signInput)

	if err != nil { return nil, err }

	return signOutput.Signature, nil
}

func (m *KmsKeysManager) AddKey(keyRole string, key PrivateKeyHandle) error {
	return fmt.Errorf("cannot add key to KMS, either generate the key or import existing one")
}
