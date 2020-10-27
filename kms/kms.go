package main

import (
	"flag"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"time"


)

// Uploads a file to S3 given a bucket and object key. Also takes a duration
// value to terminate the update if it doesn't complete within that time.
//
// The AWS Region needs to be provided in the AWS shared config or on the
// environment variable as `AWS_REGION`. Credentials also must be provided
// Will default to shared config file, but can load from environment if provided.
//
// Usage:
//   # Upload myfile.txt to myBucket/myKey. Must complete within 10 minutes or will fail
//   go run withContext.go -b mybucket -k myKey -d 10m < myfile.txt
func main() {
	var bucket, key string
	var timeout time.Duration

	flag.StringVar(&bucket, "b", "", "Bucket name.")
	flag.StringVar(&key, "k", "", "Object key name.")
	flag.DurationVar(&timeout, "d", 0, "Upload timeout.")
	flag.Parse()

	// All clients require a Session. The Session provides the client with
	// shared configuration such as region, endpoint, and credentials. A
	// Session should be shared where possible to take advantage of
	// configuration and credential caching. See the session package for
	// more information.
	sess := session.Must(session.NewSession())

	region := "us-west-2"
	sess.Config.Region = &region

	// Create a new instance of the service's client with a Session.
	// Optional aws.Config values can also be provided as variadic arguments
	// to the New function. This option allows you to provide service
	// specific configuration.
	//svc := s3.New(sess)

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

	result, err := svc.CreateKey(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case kms.ErrCodeMalformedPolicyDocumentException:
				fmt.Println(kms.ErrCodeMalformedPolicyDocumentException, aerr.Error())
			case kms.ErrCodeDependencyTimeoutException:
				fmt.Println(kms.ErrCodeDependencyTimeoutException, aerr.Error())
			case kms.ErrCodeInvalidArnException:
				fmt.Println(kms.ErrCodeInvalidArnException, aerr.Error())
			case kms.ErrCodeUnsupportedOperationException:
				fmt.Println(kms.ErrCodeUnsupportedOperationException, aerr.Error())
			case kms.ErrCodeInternalException:
				fmt.Println(kms.ErrCodeInternalException, aerr.Error())
			case kms.ErrCodeLimitExceededException:
				fmt.Println(kms.ErrCodeLimitExceededException, aerr.Error())
			case kms.ErrCodeTagException:
				fmt.Println(kms.ErrCodeTagException, aerr.Error())
			case kms.ErrCodeCustomKeyStoreNotFoundException:
				fmt.Println(kms.ErrCodeCustomKeyStoreNotFoundException, aerr.Error())
			case kms.ErrCodeCustomKeyStoreInvalidStateException:
				fmt.Println(kms.ErrCodeCustomKeyStoreInvalidStateException, aerr.Error())
			case kms.ErrCodeCloudHsmClusterInvalidConfigurationException:
				fmt.Println(kms.ErrCodeCloudHsmClusterInvalidConfigurationException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
		return
	}

	fmt.Println(result)
}