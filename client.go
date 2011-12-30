package main

import (
	"crypto/openpgp"
	"crypto/openpgp/packet"
	"exp/terminal"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
)

func RemoteHash(serverUrl, path string, pgpSuffix []byte) (digest []byte, er error) {
	form := make(url.Values)
	form.Add("path", path)
	form.Add("suffix", string(pgpSuffix))
	resp, er := http.PostForm(serverUrl, form)
	if er != nil {
		return
	}
	digest, er = ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %s: %s", resp.Status, digest)
	}
	return
}

func PromptPassphrase(k *packet.PrivateKey) ([]byte, error) {
	fmt.Printf("Enter passphrase for key ID %x: ", k.KeyId)
	pass, er := terminal.ReadPassword(0)
	fmt.Println("done.")
	return pass, er
}

func GetSigner(keyringPath string, id string) (*openpgp.Entity, error) {
	f, er := os.Open(keyringPath)
	if er != nil {
		return nil, er
	}
	defer f.Close()

	entities, err := openpgp.ReadKeyRing(f)
	if err != nil {
		return nil, err
	}
	for _, entity := range entities {
		switch {
		case entity.PrivateKey == nil:
			continue
		case !entity.PrivateKey.Encrypted:
			return entity, nil
		default:
			passphrase, err := PromptPassphrase(entity.PrivateKey)
			if err == nil {
				err = entity.PrivateKey.Decrypt(passphrase)
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "could not decrypt private key: %s\n", err)
				continue
			}
			return entity, nil
		}
	}
	return nil, fmt.Errorf("no suitable private key found")
}

func main() {
	defaultKeyring := os.Getenv("HOME") + "/.gnupg/secring.gpg"
	keyring := flag.String("keyring", defaultKeyring, "path to a binary, secret keyring")
	keyid := flag.String("id", "", "(not implemented) key ID to use")
	server := flag.String("server", "http://localhost:10022/hash", "remote hash server address")
	flag.Parse()

	remotepath := flag.Arg(0)
	if remotepath == "" {
		fmt.Println("no remote filename specified!")
		return
	}

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
