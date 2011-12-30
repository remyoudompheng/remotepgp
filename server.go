package main

import (
	"crypto"
	"flag"
	"fmt"
	"hash"
	"http"
	"io"
	"os"
)

func HashFile(filepath string) (hash.Hash, os.Error) {
	h := crypto.SHA256.New()
	f, er := os.Open(filepath)
	if er != nil {
		return nil, fmt.Errorf("could not open file %s for reading: %s", filepath, er)
	}
	defer f.Close()
	_, er = io.Copy(h, f)
	if er != nil {
		return nil, fmt.Errorf("hashing error: %s")
	}

	return h, nil
}

func GetHash(filepath string, pgpSuffix []byte) (digest []byte, er os.Error) {
	h, er := HashFile(filepath)
	if er != nil {
		return nil, er
	}
	h.Write(pgpSuffix)
	digest = h.Sum()
	return
}

func handler(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "invalid HTTP method %s used", req.Method)
		return
	}

	filepath := req.Form.Get("path")
	suffix := req.Form.Get("suffix")
	if filepath == "" || suffix == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "invalid/missing path (got %q) or pgpsuffix (got %q)", filepath, suffix)
		return
	}

	digest, er := GetHash(filepath, []byte(suffix))
	if er != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "error: %s", er)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(digest)
}

func main() {
  listenaddr := flag.String("addr", "localhost:10022", "address to listen on")
  flag.Parse()

  http.HandleFunc("/hash", handler)
  http.ListenAndServe(*listenaddr, nil)
}
