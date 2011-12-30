package main

import (
	"crypto"
	"crypto/dsa"
	"crypto/openpgp"
	pgperror "crypto/openpgp/error"
	"crypto/openpgp/packet"
	"crypto/rsa"
	"http"
	"io"
	"io/ioutil"
	"os"
	"crypto/rand"
	"flag"
	"path"
	"strconv"
	"time"
	"unsafe"
	"url"
)

// copied from crypto/openpgp/packet.(*Signature).Sign()
func MakeSignature(pgpsig *packet.Signature, priv *packet.PrivateKey, digest []byte) (err os.Error) {
	sig := (*Signature)(unsafe.Pointer(pgpsig))
	switch priv.PubKeyAlgo {
	case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSASignOnly:
		sig.RSASignature.bytes, err = rsa.SignPKCS1v15(rand.Reader, priv.PrivateKey.(*rsa.PrivateKey), sig.Hash, digest)
		sig.RSASignature.bitLength = uint16(8 * len(sig.RSASignature.bytes))
	case packet.PubKeyAlgoDSA:
		r, s, err := dsa.Sign(rand.Reader, priv.PrivateKey.(*dsa.PrivateKey), digest)
		if err == nil {
			sig.DSASigR.bytes = r.Bytes()
			sig.DSASigR.bitLength = uint16(8 * len(sig.DSASigR.bytes))
			sig.DSASigS.bytes = s.Bytes()
			sig.DSASigS.bitLength = uint16(8 * len(sig.DSASigS.bytes))
		}
	default:
		err = pgperror.UnsupportedError("public key algorithm: " + strconv.Itoa(int(sig.PubKeyAlgo)))
	}

	return
}

func RemoteHash(serverUrl, path string, pgpSuffix []byte) (digest []byte, er os.Error) {
	form := make(url.Values)
	form.Add("path", path)
	form.Add("suffix", string(pgpSuffix))
	resp, er := http.PostForm(serverUrl, form)
	if er != nil {
		return
	}

	digest, er = ioutil.ReadAll(resp.Body)
	return
}

func RemoteDetachSign(w io.Writer, signer *openpgp.Entity, remoteUrl, path string) os.Error {
	if signer.PrivateKey == nil {
		return pgperror.InvalidArgumentError("signing key doesn't have a private key")
	}
	if signer.PrivateKey.Encrypted {
		return pgperror.InvalidArgumentError("signing key is encrypted")
	}

	sig := new(packet.Signature)
	sig.SigType = packet.SigTypeBinary
	sig.PubKeyAlgo = signer.PrivateKey.PubKeyAlgo
	sig.Hash = crypto.SHA256
	sig.CreationTime = uint32(time.Seconds())
	sig.IssuerKeyId = &signer.PrivateKey.KeyId

	// prepare outSubpackets and hash suffix.
	sig.Sign(nil, nil)
	pgpSuffix := sig.HashSuffix
	digest, err := RemoteHash(remoteUrl, path, pgpSuffix)
	if err != nil {
		return err
	}

	err = MakeSignature(sig, signer.PrivateKey, digest)
	if err != nil {
		return err
	}

	return sig.Serialize(w)
}

func PromptPassphrase(k *packet.PrivateKey) ([]byte, os.Error) {
   
}

func GetSigner(keyringPath string, id string) (*openpgp.Entity, os.Error) {
	f, er := os.Open(keyringPath)
	if er != nil {
		return nil, er
	}
	defer f.Close()

	entities, err := openpgp.ReadKeyRing(f)
	for _, entity := range entities {
		if entity.PrivateKey != nil {
			passphrase := PromptPassphrase(entity.PrivateKey)
			err = entity.PrivateKey.Decrypt(passphrase)
			if err != nil {
				fmt.Fprintf(os.Stderr, "could not decrypt private key: %s\n", err)
			} else {
				return entity
			}
		}
	}
	return fmt.Errorf("no suitable private key found")
}

func main() {
	defaultKeyring := os.Getenv("HOME") + ".gnupg/secring.gpg"
	keyring := flag.String("keyring", defaultKeyring, "path to a binary, secret keyring")
	keyid := flag.String("id", "", "(not implemented) key ID to use")
	server := flag.String("server", "localhost:10022", "remote hash server address")
	flag.Parse()

	remotepath := flag.Arg(0)
	signer, err := GetSigner(*keyring, *keyid)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	sigpath := path.Base(remotepath) + ".sig"
	sigfile, err := os.Create(sigpath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not create signature file %s: %s\n", sigpath, err)
		return
	}

	err = RemoteDetachSign(sigfile, signer, *server, remotepath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
