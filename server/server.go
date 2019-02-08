package main

import (
	"crypto"
	"flag"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
)

func HashFile(filepath string) (hash.Hash, error) {
	h := crypto.SHA256.New()
	f, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("could not open file %s for reading: %s", filepath, err)
	}
	defer f.Close()
	_, err = io.Copy(h, f)
	if err != nil {
		return nil, fmt.Errorf("hashing error: %s", err)
	}

	return h, nil
}

func GetHash(filepath string, pgpSuffix []byte) (digest []byte, er error) {
	h, er := HashFile(filepath)
	if er != nil {
		return nil, er
	}
	h.Write(pgpSuffix)
	digest = h.Sum(nil)
	return
}

func handler(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "invalid HTTP method %s used", req.Method)
		return
	}

	req.ParseForm()
	filepath := req.Form.Get("path")
	suffix := req.Form.Get("suffix")
	if filepath == "" || suffix == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "invalid/missing path (got %q) or pgpsuffix (got %q)", filepath, suffix)
		return
	}

	fmt.Println("request to hash ", filepath)
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
