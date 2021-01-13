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
	"net/http"
	"net/url"
	"reflect"
)

type Notification struct {
	Type             string
	MessageId        string
	TopicArn         string
	Subject          string
	Message          string
	Timestamp        string
	SignatureVersion string
	Signature        string
	SigningCertURL   string
	UnsubscribeURL   string
}

func (sns *Notification) VerifySignature(awsRegion string) (bool, error) {
	if sns.SignatureVersion != "1" {
		return false, errors.New(fmt.Sprint("unknown signature version"))
	}

	if ok, err := sns.verifyCertURL(awsRegion); !ok || err != nil {
		return false, errors.New(fmt.Sprintf("error verify CertURL: %v", err))
	}

	var err error

	var buffer bytes.Buffer
	signatureKeys := []string{"Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type"}
	for _, key := range signatureKeys {
		r := reflect.ValueOf(sns)
		f := reflect.Indirect(r).FieldByName(key)
		keyString := f.String()
		if key != "Subject" || keyString != "" {
			buffer.WriteString(key + "\n")
			buffer.WriteString(keyString + "\n")
		}
	}

	var base64DecodedSignature []byte
	if base64DecodedSignature, err = base64.StdEncoding.DecodeString(sns.Signature); err != nil {
		return false, errors.New(fmt.Sprintf("base64 decoding error: %v", err))
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

	p, _ := pem.Decode(body)

	var cert *x509.Certificate
	if cert, err = x509.ParseCertificate(p.Bytes); err != nil {
		return false, errors.New(fmt.Sprintf("error parsing certificate: %v", err))
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
