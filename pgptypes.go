// Copyright 2011 The Go Authors. All rights reserved.
// Part of this code is a modification of package crypto/openpgp/packet
// from Go standard library.

package main

import (
	"crypto"
	"crypto/dsa"
	"crypto/rsa"
	"fmt"
	"io"
	"strconv"
	"time"
	"unsafe"

	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/errors"
	"code.google.com/p/go.crypto/openpgp/packet"
)

type parsedMPI struct {
	bytes     []byte
	bitLength uint16
}

type outputSubpacket struct {
	hashed        bool // true if this subpacket is in the hashed area.
	subpacketType uint8
	isCritical    bool
	contents      []byte
}

type Signature struct {
	SigType    packet.SignatureType
	PubKeyAlgo packet.PublicKeyAlgorithm
	Hash       crypto.Hash

	// HashSuffix is extra data that is hashed in after the signed data.
	HashSuffix []byte
	// HashTag contains the first two bytes of the hash for fast rejection
	// of bad signed data.
	HashTag      [2]byte
	CreationTime time.Time

	RSASignature     parsedMPI
	DSASigR, DSASigS parsedMPI

	// rawSubpackets contains the unparsed subpackets, in order.
	rawSubpackets []outputSubpacket

	// The following are optional so are nil when not included in the
	// signature.

	SigLifetimeSecs, KeyLifetimeSecs                        *uint32
	PreferredSymmetric, PreferredHash, PreferredCompression []uint8
	IssuerKeyId                                             *uint64
	IsPrimaryId                                             *bool

	// FlagsValid is set if any flags were given. See RFC 4880, section
	// 5.2.3.21 for details.
	FlagsValid                                                           bool
	FlagCertify, FlagSign, FlagEncryptCommunications, FlagEncryptStorage bool

	outSubpackets []outputSubpacket
}

func prepareSign(sig *packet.Signature) {
	defer func() {
		_ = recover()
	}()
	sig.Sign(nil, nil, nil)
}

func RemoteDetachSign(w io.Writer, signer *openpgp.Entity, remoteUrl, path string) error {
	if signer.PrivateKey == nil {
		return errors.InvalidArgumentError("signing key doesn't have a private key")
	}
	if signer.PrivateKey.Encrypted {
		return errors.InvalidArgumentError("signing key is encrypted")
	}

	sig := new(packet.Signature)
	sig.SigType = packet.SigTypeBinary
	sig.PubKeyAlgo = signer.PrivateKey.PubKeyAlgo
	sig.Hash = crypto.SHA256
	sig.CreationTime = time.Now()
	sig.IssuerKeyId = &signer.PrivateKey.KeyId

	// prepare outSubpackets and hash suffix.
	prepareSign(sig)
	pgpSuffix := sig.HashSuffix
	digest, err := RemoteHash(remoteUrl, path, pgpSuffix)
	if err != nil {
		return fmt.Errorf("could not fetch remote hash: %s", err)
	}

	err = MakeSignature(sig, signer.PrivateKey, digest)
	if err != nil {
		return fmt.Errorf("could not build signature: %s", err)
	}

	return sig.Serialize(w)
}

// copied from crypto/openpgp/packet.(*Signature).Sign()
func MakeSignature(pgpsig *packet.Signature, priv *packet.PrivateKey, digest []byte) (err error) {
	sig := (*Signature)(unsafe.Pointer(pgpsig))
	var config *packet.Config
	switch priv.PubKeyAlgo {
	case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSASignOnly:
		sig.RSASignature.bytes, err = rsa.SignPKCS1v15(config.Random(), priv.PrivateKey.(*rsa.PrivateKey), sig.Hash, digest)
		sig.RSASignature.bitLength = uint16(8 * len(sig.RSASignature.bytes))
	case packet.PubKeyAlgoDSA:
		dsaPriv := priv.PrivateKey.(*dsa.PrivateKey)

		r, s, err := dsa.Sign(config.Random(), dsaPriv, digest)
		if err == nil {
			sig.DSASigR.bytes = r.Bytes()
			sig.DSASigR.bitLength = uint16(8 * len(sig.DSASigR.bytes))
			sig.DSASigS.bytes = s.Bytes()
			sig.DSASigS.bitLength = uint16(8 * len(sig.DSASigS.bytes))
		}
	default:
		err = errors.UnsupportedError("public key algorithm: " + strconv.Itoa(int(sig.PubKeyAlgo)))
	}

	return
}
