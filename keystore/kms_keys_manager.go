package keystore

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/flynn/go-tuf/data"
)

type KmsKeysManager struct // implements KeysManager
{

}

type KmsPrivateKeyHandle struct // implements PrivateKeyHandle
{
	keyId string
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

	service  := h.manager.getKmsService()

	input := &kms.GetPublicKeyInput{
		KeyId:       &h.keyId,
	}
	
	output, err := service.GetPublicKey(input)
	if err != nil {
		return nil, err
	}
	key := &data.Key{
		Type:  data.KeyTypeECDSA_SHA2_P256,	// TODO
		Value: data.KeyValue{Public: output.PublicKey },
	}

	return key, nil
}

func NewKmsKeysManager() *KmsKeysManager {
	return &KmsKeysManager{}
}

func (m *KmsKeysManager) getKmsService() *kms.KMS {
	sess := session.Must(session.NewSession())

	region := "us-west-2"
	sess.Config.Region = &region

	service := kms.New(sess)

	return service
}



func (m *KmsKeysManager) GenerateKey(keyRole string, keyType string) (PrivateKeyHandle, error) {
	service := m.getKmsService()
	description := "This is TUF key for " + keyRole + " role."
	createKeyInput := &kms.CreateKeyInput{

		Description: &description,
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

	createKeyOutput, err := service.CreateKey(createKeyInput)
	if err != nil {
		return nil, err
	}

	privateKeyHandle := &KmsPrivateKeyHandle{manager: m, keyId: *createKeyOutput.KeyMetadata.KeyId}
	publicKey, err := privateKeyHandle.GetPublicKey()
	if err != nil {
		return nil, err
	}

	alias := "alias/TUF_" + keyRole + "_" + publicKey.ID()
	createInput := &kms.CreateAliasInput{
		AliasName:   &alias,
		TargetKeyId: createKeyOutput.KeyMetadata.KeyId,
	}
	_, err = service.CreateAlias(createInput)
	if err != nil {
		return nil, err
	}

	return privateKeyHandle, nil
}