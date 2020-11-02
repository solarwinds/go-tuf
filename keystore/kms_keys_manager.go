package keystore

import (
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/flynn/go-tuf/data"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
)

type KmsKeysManager struct // implements KeysManager
{
	dir 	           string
	entries            []KmsKeyEntry
	entriesStorePath   string
	loadKeyEntriesOnce sync.Once
}

type KmsPrivateKeyHandle struct // implements PrivateKeyHandle
{
	keyId   string
	manager *KmsKeysManager
}

type KmsPublicDataHandle struct // implements PublicDataHandle
{
	publicKey []byte
}

func (k KmsPublicDataHandle) ID() string {
	panic("implement me")
}

func (k KmsPublicDataHandle) GetKey() *data.Key {
	panic("implement me")
}

func (h *KmsPrivateKeyHandle) GetPublicKey() (*data.Key, error) {

	kmsService, _ := h.manager.getServices()

	input := &kms.GetPublicKeyInput{
		KeyId:       &h.keyId,
	}
	
	output, err := kmsService.GetPublicKey(input)
	if err != nil {
		return nil, err
	}
	key := &data.Key{
		Type:  data.KeyTypeECDSA_SHA2_P256,	// TODO
		Value: data.KeyValue{Public: output.PublicKey },
	}

	return key, nil
}

func NewKmsKeysManager(dir string) *KmsKeysManager {

	entriesStorePath := path.Join(dir, "kms", "kms.json")
	return &KmsKeysManager{dir: dir, entriesStorePath: entriesStorePath, entries: []KmsKeyEntry{}}
}

func (m *KmsKeysManager) getServices() (*kms.KMS, *sts.STS) {
	sess := session.Must(session.NewSession())

	region := "us-west-2"
	sess.Config.Region = &region

	kmsService := kms.New(sess)
	stsService := sts.New(sess)

	return kmsService, stsService
}



func (m *KmsKeysManager) GenerateKey(keyRole string, keyType string) (PrivateKeyHandle, error) {
	kmsService, stsService := m.getServices()
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

	customerMasterKeySec := kms.DataKeyPairSpecRsa2048
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

	privateKeyHandle := &KmsPrivateKeyHandle{manager: m, keyId: *createKeyOutput.KeyMetadata.KeyId}
	publicKey, err := privateKeyHandle.GetPublicKey()
	if err != nil { return nil, err }

	createInput := &kms.CreateAliasInput{
		AliasName:   aws.String("alias/TUF_" + keyRole + "_" + string(publicKey.ID()[0:8])),
		TargetKeyId: createKeyOutput.KeyMetadata.KeyId,
	}
	_, err = kmsService.CreateAlias(createInput)
	if err != nil { return nil, err }

	tagInput := &kms.TagResourceInput{
		KeyId: createKeyOutput.KeyMetadata.KeyId,
		Tags: []*kms.Tag{
			{
				TagKey:   aws.String("TUF Key Id"),
				TagValue: aws.String(publicKey.ID()),
			},
		},
	}
	_, err = kmsService.TagResource(tagInput)
	if err != nil { return nil, err }

	err = m.addKeyEntry(&KmsKeyEntry	{ Arn: *createKeyOutput.KeyMetadata.Arn, PublicKeyId:publicKey.ID() })
	if err != nil { return nil, err }

	return privateKeyHandle, nil
}

func (m *KmsKeysManager) ImportKey(externalKeyId string) (PrivateKeyHandle, error) {
	kmsService, _ := m.getServices()

	describeKeyInput := &kms.DescribeKeyInput{
		KeyId: aws.String(externalKeyId),
	}

	describeKeyOutput, err := kmsService.DescribeKey(describeKeyInput)
	if err != nil { return nil, err }

	algorithms := describeKeyOutput.KeyMetadata.EncryptionAlgorithms
	for _, algorithm := range algorithms {
		fmt.Println(algorithm)
	}

	privateKeyHandle := &KmsPrivateKeyHandle{manager: m, keyId: *describeKeyOutput.KeyMetadata.KeyId}
	publicKey, err := privateKeyHandle.GetPublicKey()
	if err != nil { return nil, err }

	err = m.addKeyEntry(&KmsKeyEntry	{ Arn: *describeKeyOutput.KeyMetadata.Arn, PublicKeyId:publicKey.ID() })
	if err != nil { return nil, err }

	return privateKeyHandle, nil
}

func (m *KmsKeysManager) createDirs() error {
	for _, dir := range []string{"kms"} {
		if err := os.MkdirAll(filepath.Join(m.dir, dir), 0755); err != nil {
			return err
		}
	}
	return nil
}

func (m *KmsKeysManager) addKeyEntry(entry *KmsKeyEntry) error {
	var err error = nil
	m.loadKeyEntriesOnce.Do(func() {
		err = m.loadKeyEntries()
	})

	if err != nil {
		return err
	}

	for _, e := range m.entries {
		if e.PublicKeyId == entry.PublicKeyId {
			return nil
		}
	}

	m.entries = append(m.entries, *entry)
	return m.saveKeyEntries()
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

type KmsKeyEntry struct {
	Arn         string `json:"arn"`
	PublicKeyId string `json:"publicKeyId"`
}