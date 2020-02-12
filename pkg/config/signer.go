/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/msp"
)

var (
	// curveHalfOrders contains the precomputed curve group orders halved.
	// It is used to ensure that signature' S value is lower or equal to the
	// curve group order halved. We accept only low-S signatures.
	// They are precomputed for efficiency reasons.
	curveHalfOrders = map[elliptic.Curve]*big.Int{
		elliptic.P224(): new(big.Int).Rsh(elliptic.P224().Params().N, 1),
		elliptic.P256(): new(big.Int).Rsh(elliptic.P256().Params().N, 1),
		elliptic.P384(): new(big.Int).Rsh(elliptic.P384().Params().N, 1),
		elliptic.P521(): new(big.Int).Rsh(elliptic.P521().Params().N, 1),
	}
)

type ecdsaSignature struct {
	R, S *big.Int
}

// Signer ...
type Signer struct {
	cert       *x509.Certificate
	mspId      string
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
}

// NewSigner creates a signer that being used to sign configuration updates.
func NewSigner(pemCert []byte, skCert []byte, mspID string) (*Signer, error) {
	if mspID == "" {
		return nil, errors.New("failed to create new signer, mspID can not be empty")
	}

	cert, err := getCertFromPem(pemCert)
	if err != nil {
		return nil, fmt.Errorf("failed to get cert from pem: %v", err)
	}

	publicKey, err := ecdsaPublicKeyImport(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to get ECDSA public key: %v", err)
	}

	skPemKey, _ := pem.Decode(skCert)
	if skPemKey == nil {
		return nil, errors.New("failed to decode private key from pem")
	}

	privatekey, err := ecdsaPrivateKeyImport(skPemKey.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to get ECDSA private key: %v", err)
	}

	signer := &Signer{
		cert:       cert,
		mspId:      mspID,
		privateKey: privatekey,
		publicKey:  publicKey,
	}
	return signer, nil
}

// Serialize returns a byte array representation of this identity
func (s *Signer) Serialize() ([]byte, error) {
	pb := &pem.Block{Bytes: s.cert.Raw, Type: "CERTIFICATE"}
	pemBytes := pem.EncodeToMemory(pb)
	if pemBytes == nil {
		return nil, errors.New("failed to encode pem block")
	}

	// We serialize identities by prepending the MSPID and appending the ASN.1 DER content of the cert
	sID := &msp.SerializedIdentity{Mspid: s.mspId, IdBytes: pemBytes}
	idBytes := MarshalOrPanic(sID)

	return idBytes, nil
}

// Public returns the public key of the signer.
func (s *Signer) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign performs ECDSA sign with signer's private key on given digest.
func (s *Signer) Sign(reader io.Reader, digest []byte) (signature []byte, err error) {
	if reader == nil {
		return nil, errors.New("failed to sign, reader can not be nil")
	}

	rr, ss, err := ecdsa.Sign(reader, s.privateKey, digest)
	if err != nil {
		return nil, err
	}

	ss, _, err = toLowS(&s.privateKey.PublicKey, ss)
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(ecdsaSignature{rr, ss})
}

// newSignatureHeader returns a SignatureHeader with a valid nonce.
func (s *Signer) CreateSignatureHeader() (*common.SignatureHeader, error) {
	creator, err := s.Serialize()
	if err != nil {
		return nil, err
	}
	nonce, err := createNonce()
	if err != nil {
		return nil, err
	}

	return &common.SignatureHeader{
		Creator: creator,
		Nonce:   nonce,
	}, nil
}

// createNonce generates a nonce using the common/crypto package.
func createNonce() ([]byte, error) {
	nonce, err := getRandomNonce()
	if err != nil {

		return nil, fmt.Errorf("failed to generate random nonce: %s", err)
	}
	return nonce, nil
}

func getRandomNonce() ([]byte, error) {
	key := make([]byte, 24)

	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get random bytes: %s", err)
	}
	return key, nil
}

// isLowS checks that s is a low-S.
func isLowS(k *ecdsa.PublicKey, s *big.Int) (bool, error) {
	halfOrder, ok := curveHalfOrders[k.Curve]
	if !ok {
		return false, fmt.Errorf("curve not recognized [%s]", k.Curve)
	}

	return s.Cmp(halfOrder) != 1, nil

}

// toLowS converts s to low-S.
func toLowS(k *ecdsa.PublicKey, s *big.Int) (*big.Int, bool, error) {
	lowS, err := isLowS(k, s)
	if err != nil {
		return nil, false, err
	}

	if !lowS {
		// Set s to N - s that will be then in the lower part of signature space
		// less or equal to half order
		s.Sub(k.Params().N, s)

		return s, true, nil
	}

	return s, false, nil
}

// getCertFromPem which given pem encoded cert and decode into x509 certificate.
// idBytes will be pem encoded certs that provided from MSP.
func getCertFromPem(pemBytes []byte) (*x509.Certificate, error) {
	// Decode the pem bytes
	pemCert, _ := pem.Decode(pemBytes)
	if pemCert == nil {
		return nil, fmt.Errorf("failed to decode pem bytes: %v", pemBytes)
	}

	cert, err := x509.ParseCertificate(pemCert.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse x509 cert: %v", err)
	}

	return cert, nil
}

// ecdsaPublicKeyImport imports the public key from x509 certificate.
func ecdsaPublicKeyImport(x509Cert *x509.Certificate) (*ecdsa.PublicKey, error) {
	pk := x509Cert.PublicKey

	lowLevelKey, ok := pk.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("certificate does not contain valid ECDSA public key")
	}

	return lowLevelKey, nil
}

// ecdsaPrivateKeyImport imports the private key from private key bytes.
func ecdsaPrivateKeyImport(privBytes []byte) (*ecdsa.PrivateKey, error) {
	lowLevelKey, err := x509.ParsePKCS8PrivateKey(privBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid key type. The DER must contain an ecdsa.PrivateKey: %v", err)
	}

	ecdsaSK, ok := lowLevelKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("failed to cast private key bytes to ECDSA private key")
	}

	return ecdsaSK, nil
}
