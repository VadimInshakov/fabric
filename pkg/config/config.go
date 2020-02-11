/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/msp"
	"github.com/pkg/errors"
)

// Signer is an interface which wraps the Sign method.
//
// Sign signs message bytes and returns the signature or an error on failure.
//type Signer interface {
//	Sign(message []byte) ([]byte, error)
//}

//// Serializer is an interface which wraps the Serialize function.
////
//// Serialize converts an identity to bytes.  It returns an error on failure.
//type Serializer interface {
//	Serialize() ([]byte, error)
//}

//// SignerSerializer groups the Sign and Serialize methods.
//type SignerSerializer interface {
//	Signer
//	Serializer
//}

type Signer struct {
	SignerCert []byte
	MSPId      string
}

// Serialize returns a byte array representation of this identity
func (s *Signer) Serialize() ([]byte, error) {
	pb := &pem.Block{Bytes: s.SignerCert, Type: "CERTIFICATE"}
	pemBytes := pem.EncodeToMemory(pb)
	if pemBytes == nil {
		return nil, errors.New("encoding of identity failed")
	}

	// We serialize identities by prepending the MSPID and appending the ASN.1 DER content of the cert
	sId := &msp.SerializedIdentity{Mspid: s.MSPId, IdBytes: pemBytes}
	idBytes, err := proto.Marshal(sId)
	if err != nil {
		return nil, errors.Wrapf(err, "could not marshal structure for signer")
	}

	return idBytes, nil
}

func (s *Signer) Sign(rand io.Reader, digest []byte /*, opts SignerOpts*/) (signature []byte, err error) {

}

func SignChannelUpdate(configUpdate *common.ConfigUpdate, signer Signer) (*common.ConfigSignature, error) {
	signatureHeader, err := newSignatureHeader(signer)
	if err != nil {
		return nil, err
	}

	configSignature := &common.ConfigSignature{
		SignatureHeader: MarshalOrPanic(signatureHeader),
	}
	configUpdateBytes := MarshalOrPanic(configUpdate)
	// configSignature.Signature, err = signer.Sign(concatenateBytes(configSignature.SignatureHeader, configUpdateBytes))
	configSignature.Signature, err = signer.Sign(rand.Reader, concatenateBytes(configSignature.SignatureHeader, configUpdateBytes))
	if err != nil {
		return nil, err
	}

	return configSignature, nil
}

// MarshalOrPanic serializes a protobuf message and panics if this
// operation fails
func MarshalOrPanic(pb proto.Message) []byte {
	data, err := proto.Marshal(pb)
	if err != nil {
		panic(err)
	}
	return data
}

// concatenateBytes is useful for combining multiple arrays of bytes, especially for
// signatures or digests over multiple fields
func concatenateBytes(data ...[]byte) []byte {
	finalLength := 0
	for _, slice := range data {
		finalLength += len(slice)
	}
	result := make([]byte, finalLength)
	last := 0
	for _, slice := range data {
		for i := range slice {
			result[i+last] = slice[i]
		}
		last += len(slice)
	}
	return result
}

// newSignatureHeader returns a SignatureHeader with a valid nonce.
func newSignatureHeader(signer Signer) (*common.SignatureHeader, error) {
	creator, err := signer.Serialize()
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

		return nil, fmt.Errorf("error generating random nonce: %s", err)
	}
	return nonce, nil
}

func getRandomNonce() ([]byte, error) {
	key := make([]byte, 24)

	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("error getting random bytes: %s", err)
	}
	return key, nil
}
