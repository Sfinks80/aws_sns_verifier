# AWS SNS Verifier
Simple package for verifying the signature of the AWS SNS Message

## Installation

```shell
go get github.com/Sfinks80/aws_sns_verifier
```

## Usage

```go
package main

import (
	"encoding/json"
	"fmt"

	sns "github.com/Sfinks80/aws_sns_verifier"
)

func main() {
	body := []byte(`{
    "Type": "Notification",
    "MessageId": "some",
    "TopicArn": "some",
    "Subject": "some",
    "Message": "some",
    "Timestamp": "some",
    "SignatureVersion": "1",
    "Signature": "some",
    "SigningCertURL": "some",
    "UnsubscribeURL": "some"
}`)

	notify := &sns.Notification{}
	json.Unmarshal(body, notify)
	
	awsRegion := "eu-central-1"
	valid, _ := notify.VerifySignature(awsRegion)
	
	fmt.Println(valid)
}
```
