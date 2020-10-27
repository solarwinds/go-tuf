package keystore

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
)

type KmsKeysManager struct // implements KeysManager
{

}

type KmsPrivateKeyHandle struct // implements PrivateKeyHandle
{
	keyId string
}

func (k KmsPrivateKeyHandle) GetPublicData() PublicDataHandle {
	panic("implement me")
}

func NewKmsKeysManager() *KmsKeysManager {
	return &KmsKeysManager{

	}
}


func (m *KmsKeysManager) GenerateKey(keyRole string, keyType string) (PrivateKeyHandle, error) {
	sess := session.Must(session.NewSession())

	region := "us-west-2"
	sess.Config.Region = &region

	svc := kms.New(sess)

	input := &kms.CreateKeyInput{
		Tags: []*kms.Tag{
			{
				TagKey:   aws.String("CreatedBy"),
				TagValue: aws.String("ExampleUser"),
			},
		},
	}

	customerMasterKeySec := kms.DataKeyPairSpecRsa2048
	input.CustomerMasterKeySpec = &customerMasterKeySec

	keyUsageTypeSignVerify := kms.KeyUsageTypeSignVerify
	input.KeyUsage = &keyUsageTypeSignVerify

	output, err := svc.CreateKey(input)

	if err != nil {
		return nil, err
	}

	return &KmsPrivateKeyHandle{keyId: *output.KeyMetadata.KeyId}, nil
}