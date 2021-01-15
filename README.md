# AWS SNS Verifier
Simple package for verifying the signature of the AWS SNS Message

## Installation

```shell
go get github.com/Sfinks80/aws_sns_verifier
```

## Usage

To enable debug-mode, please set the ENV variable `SNS_VERIFIER_DEBUG=true`

```go
package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	sns "github.com/Sfinks80/aws_sns_verifier"
)

func main() {
    // ...
}
         
func Handler() http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if !sns.IsValidType(r.Header.Get("x-amz-sns-message-type")) {
            fmt.Println("error invalid message type")
            return
        }
    
        body := []byte(`{
            "Type" : "SubscriptionConfirmation",
            "MessageId" : "165545c9-2a5c-472c-8df2-7ff2be2b3b1b",
            "Token" : "2336412f37f...",
            "TopicArn" : "arn:aws:sns:us-west-2:123456789012:MyTopic",
            "Message" : "You have chosen to subscribe to the topic arn:aws:sns:us-west-2:123456789012:MyTopic.\nTo confirm the subscription, visit the SubscribeURL included in this message.",
            "SubscribeURL" : "https://sns.us-west-2.amazonaws.com/?Action=ConfirmSubscription&TopicArn=arn:aws:sns:us-west-2:123456789012:MyTopic&Token=2336412f37...",
            "Timestamp" : "2012-04-26T20:45:04.751Z",
            "SignatureVersion" : "1",
            "Signature" : "EXAMPLEpH+...",
            "SigningCertURL" : "https://sns.us-west-2.amazonaws.com/SimpleNotificationService-f3ecfb7224c7233fe7bb5f59f96de52f.pem"
        }`)
    
        notify := &sns.Notification{}
        json.Unmarshal(body, notify)
	
        valid, _ := notify.VerifySignature("eu-central-1")
        
        fmt.Println(valid)
    }
}
```
