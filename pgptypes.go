package main

import (
	"crypto"
	"crypto/openpgp/packet"
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
  CreationTime uint32 // Unix epoch time

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


