/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"io"
	"math/big"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/gogo/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/msp"
)

var (
	publicKey = `
-----BEGIN CERTIFICATE-----
MIICGTCCAb+gAwIBAgIQQq8GNRbXzLdJ0lBn7bLZ0DAKBggqhkjOPQQDAjBzMQsw
CQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZy
YW5jaXNjbzEZMBcGA1UEChMQb3JnMS5leGFtcGxlLmNvbTEcMBoGA1UEAxMTY2Eu
b3JnMS5leGFtcGxlLmNvbTAeFw0yMDAyMTExNTQ0MDBaFw0zMDAyMDgxNTQ0MDBa
MFsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1T
YW4gRnJhbmNpc2NvMR8wHQYDVQQDDBZBZG1pbkBvcmcxLmV4YW1wbGUuY29tMFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpKK27+FChOFSQxXmE+w/GeO7a3UexDla
NvCJ4GamyCLX61X9mmCC3u8GlK9zc4z0pDvHTU5NZXqk1sL8smGSM6NNMEswDgYD
VR0PAQH/BAQDAgeAMAwGA1UdEwEB/wQCMAAwKwYDVR0jBCQwIoAgbPvqKNmresAX
ijaYjpWsZGAhCGrTe/TKlAaNf+9PsXUwCgYIKoZIzj0EAwIDSAAwRQIhAPB2xF12
W5Lp4aId1DxYPkcPD6Nioi1fHz6HbvVia4HQAiBappbdMZdWYMA4zDKOEHBHlTGp
3vi+hSyvpIgnxWJV1w==
-----END CERTIFICATE-----
`

	privateKey = `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgp9Bb9z/o2Wo5mV8G
FdHuxhN9eS36RQ+1zMrygkEpjxehRANCAASkorbv4UKE4VJDFeYT7D8Z47trdR7E
OVo28IngZqbIItfrVf2aYILe7waUr3NzjPSkO8dNTk1leqTWwvyyYZIz
-----END PRIVATE KEY-----
`
)

func TestNewSigner(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		gt := NewGomegaWithT(t)
		signer, err := NewSigner([]byte(publicKey), []byte(privateKey), "test-msp")
		gt.Expect(err).NotTo(HaveOccurred())
		gt.Expect(signer.MSPId).To(Equal("test-msp"))
		gt.Expect(signer.Cert.Subject.CommonName).To(Equal("Admin@org1.example.com"))
	})

	tests := []struct {
		spec        string
		publicKey   []byte
		privateKey  []byte
		mspID       string
		expectedErr string
		matchErr    bool
	}{
		{
			spec:        "nil public key",
			publicKey:   nil,
			privateKey:  []byte(privateKey),
			mspID:       "test-msp",
			expectedErr: "failed to get cert from pem: failed to decode pem bytes: []",
			matchErr:    true,
		},
		{
			spec:        "invalid public key",
			publicKey:   []byte("apple"),
			privateKey:  []byte(privateKey),
			mspID:       "test-msp",
			expectedErr: "failed to get cert from pem: failed to decode pem bytes",
			matchErr:    false,
		},
		{
			spec:        "public key is not a certificate",
			publicKey:   []byte(privateKey),
			privateKey:  []byte(privateKey),
			mspID:       "test-msp",
			expectedErr: "failed to get cert from pem: failed to parse x509 cert",
			matchErr:    false,
		},
		{
			spec:        "nil private key",
			publicKey:   []byte(publicKey),
			privateKey:  nil,
			mspID:       "test-msp",
			expectedErr: "failed to decode private key from pem",
			matchErr:    true,
		},
		{
			spec:        "empty mspID",
			publicKey:   []byte(publicKey),
			privateKey:  []byte(privateKey),
			expectedErr: "failed to create new signer, mspID can not be empty",
			matchErr:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.spec, func(t *testing.T) {
			gt := NewGomegaWithT(t)

			_, err := NewSigner(tc.publicKey, tc.privateKey, tc.mspID)
			if tc.matchErr {
				gt.Expect(err).To(MatchError(tc.expectedErr))
			} else {
				gt.Expect(err.Error()).To(ContainSubstring(tc.expectedErr))
			}
		})
	}
}

func TestECDSAPublicKeyImport(t *testing.T) {
	t.Run("certificate does not contain valid ecdsa publicKey", func(t *testing.T) {
		gt := NewGomegaWithT(t)
		x509cert := &x509.Certificate{PublicKey: struct{}{}}
		_, err := ecdsaPublicKeyImport(x509cert)
		gt.Expect(err).To(MatchError("certificate does not contain valid ECDSA public key"))
	})
}

func TestECDSAPrivateKeyImport(t *testing.T) {
	t.Run("nil private key", func(t *testing.T) {
		gt := NewGomegaWithT(t)
		_, err := ecdsaPrivateKeyImport(nil)
		gt.Expect(err.Error()).To(ContainSubstring("invalid key type. The DER must contain an ecdsa.PrivateKey"))
	})
}

func TestSerialize(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		gt := NewGomegaWithT(t)
		signer, err := NewSigner([]byte(publicKey), []byte(privateKey), "test-msp")
		gt.Expect(err).NotTo(HaveOccurred())

		sBytes, err := signer.Serialize()
		gt.Expect(err).NotTo(HaveOccurred())
		serializedIdentity := &msp.SerializedIdentity{}
		err = proto.Unmarshal(sBytes, serializedIdentity)
		gt.Expect(serializedIdentity.Mspid).To(Equal("test-msp"))
	})
}

func TestPublic(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		gt := NewGomegaWithT(t)
		signer, err := NewSigner([]byte(publicKey), []byte(privateKey), "test-msp")
		gt.Expect(err).NotTo(HaveOccurred())

		expectedCert, err := getCertFromPem([]byte(publicKey))
		gt.Expect(err).NotTo(HaveOccurred())
		expectedPublicKey, err := ecdsaPublicKeyImport(expectedCert)
		gt.Expect(err).NotTo(HaveOccurred())
		publicKey := signer.Public()
		gt.Expect(publicKey).To(Equal(expectedPublicKey))
	})
}

func TestSign(t *testing.T) {
	tests := []struct {
		spec        string
		reader      io.Reader
		digest      []byte
		expectedErr string
	}{
		{
			spec:        "success",
			reader:      rand.Reader,
			digest:      []byte("banana"),
			expectedErr: "",
		},
		{
			spec:        "nil reader",
			reader:      nil,
			expectedErr: "failed to sign, reader can not be nil",
		},
	}

	gt := NewGomegaWithT(t)
	signer, err := NewSigner([]byte(publicKey), []byte(privateKey), "test-msp")
	gt.Expect(err).NotTo(HaveOccurred())

	for _, tc := range tests {
		t.Run(tc.spec, func(t *testing.T) {
			gt := NewGomegaWithT(t)
			_, err = signer.Sign(tc.reader, tc.digest)
			if tc.expectedErr == "" {
				gt.Expect(err).NotTo(HaveOccurred())
			} else {
				gt.Expect(err).To(MatchError(tc.expectedErr))
			}
		})
	}
}

func TestIsLowS(t *testing.T) {
	t.Run("public key does not have a curve", func(t *testing.T) {
		gt := NewGomegaWithT(t)
		success, err := isLowS(&ecdsa.PublicKey{}, big.NewInt(1))
		gt.Expect(err.Error()).To(ContainSubstring("curve not recognized"))
		gt.Expect(success).To(BeFalse())
	})
}

func TestToLowS(t *testing.T) {
	t.Run("public key does not have a curve", func(t *testing.T) {
		gt := NewGomegaWithT(t)
		s, success, err := toLowS(&ecdsa.PublicKey{}, big.NewInt(1))
		gt.Expect(err.Error()).To(ContainSubstring("curve not recognized"))
		gt.Expect(success).To(BeFalse())
		gt.Expect(s).To(BeNil())
	})
}


