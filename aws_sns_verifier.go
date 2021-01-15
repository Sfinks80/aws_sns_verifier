package aws_sns_verifier

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"reflect"
)

type Notification struct {
	Type             string
	Subject          string
	Message          string
	MessageId        string
	Signature        string
	SignatureVersion string
	SigningCertURL   string
	SubscribeURL     string
	UnsubscribeURL   string
	TopicArn         string
	Token            string
	Timestamp        string
}

var debug = os.Getenv("SNS_VERIFIER_DEBUG") == "true"
var keysOfSignature = map[string][]string{
	"Notification":             {"Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type"},
	"SubscriptionConfirmation": {"Message", "MessageId", "SubscribeURL", "Timestamp", "Token", "TopicArn", "Type"},
	"UnsubscribeConfirmation":  {"Message", "MessageId", "SubscribeURL", "Timestamp", "Token", "TopicArn", "Type"},
}

func IsValidType(t string) bool {
	_, exist := keysOfSignature[t]
	return exist
}

func (sns *Notification) VerifySignature(awsRegion string) (bool, error) {
	if sns.SignatureVersion != "1" {
		return false, errors.New(fmt.Sprint("unknown signature version"))
	}
	if debug {
		log.Printf("SignatureVersion: %s", sns.SignatureVersion)
	}

	if ok, err := sns.verifyCertURL(awsRegion); !ok || err != nil {
		return false, errors.New(fmt.Sprintf("error verify CertURL: %v", err))
	}

	var err error

	var buffer bytes.Buffer
	signatureKeys := keysOfSignature[sns.Type]
	for _, key := range signatureKeys {
		r := reflect.ValueOf(sns)
		f := reflect.Indirect(r).FieldByName(key)
		keyString := f.String()
		if key != "Subject" || keyString != "" {
			buffer.WriteString(key + "\n")
			buffer.WriteString(keyString + "\n")
		}
	}
	if debug {
		log.Printf("SignatureString: %s", buffer.String())
	}

	var base64DecodedSignature []byte
	if base64DecodedSignature, err = base64.StdEncoding.DecodeString(sns.Signature); err != nil {
		return false, errors.New(fmt.Sprintf("base64 decoding error: %v", err))
	}
	if debug {
		log.Printf("EncoodedSignature: %s", sns.Signature)
		log.Printf("DecoodedSignature: %s", string(base64DecodedSignature))
	}

	var resp *http.Response
	if resp, err = http.Get(sns.SigningCertURL); err != nil {
		return false, errors.New(fmt.Sprintf("error loading certificate: %v", err))
	}
	defer func() { _ = resp.Body.Close() }()

	var body []byte
	if body, err = ioutil.ReadAll(resp.Body); err != nil {
		return false, errors.New(fmt.Sprintf("error reading certificate body: %v", err))
	}
	if debug {
		log.Printf("Certificate: %s", string(body))
	}

	p, _ := pem.Decode(body)
	if debug {
		log.Printf("PEM Decoded Certificate: %+v", p)
	}

	var cert *x509.Certificate
	if cert, err = x509.ParseCertificate(p.Bytes); err != nil {
		return false, errors.New(fmt.Sprintf("error parsing certificate: %v", err))
	}
	if debug {
		log.Printf("Parsed Certificate: %+v", cert)
	}

	if err = cert.CheckSignature(x509.SHA1WithRSA, buffer.Bytes(), base64DecodedSignature); err != nil {
		return false, errors.New(fmt.Sprintf("error check certificate signature: %v", err))
	}

	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return false, errors.New("error public key type assertion")
	}

	h := sha1.New()
	h.Write(buffer.Bytes())
	digest := h.Sum(nil)

	if err = rsa.VerifyPKCS1v15(pub, crypto.SHA1, digest, base64DecodedSignature); err != nil {
		return false, errors.New(fmt.Sprintf("error signature verification: %v", err))
	}

	return true, nil
}

func (sns *Notification) verifyCertURL(awsRegion string) (bool, error) {
	if debug {
		log.Printf("SigningCertURL: %s", sns.SigningCertURL)
	}

	var (
		err error
		u   *url.URL
	)

	if u, err = url.Parse(sns.SigningCertURL); err != nil {
		return false, errors.New(fmt.Sprintf("error parsing SigningCertURL: %v", err))
	}

	if u.Scheme != "https" {
		return false, errors.New(fmt.Sprintf("not secured scheme in SigningCertURL: %s", u.Scheme))
	}

	if u.Hostname() != "sns."+awsRegion+".amazonaws.com" {
		return false, errors.New(fmt.Sprintf("incorrect host in SigningCertURL: %s", u.Hostname()))
	}

	return true, nil
}
