package saltissimo

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"testing"
)

const password = "abcdefghijkl"

func TestGenerateSHA1(t *testing.T) {
	generateHexTest(t, sha1.New)
	generateB64Test(t, sha1.New)
}

func TestGenerateSHA256(t *testing.T) {
	generateHexTest(t, sha256.New)
	generateB64Test(t, sha256.New)
}

func TestGenerateSHA512(t *testing.T) {
	generateHexTest(t, sha512.New)
	generateB64Test(t, sha512.New)
}

func generateB64Test(t *testing.T, hash func() hash.Hash) {
	b64Str, salt, err := B64Hash(hash, password)
	if err != nil {
		t.Fatalf("Get error on B64Hash(): %s", err.Error())
	}

	decoded, err := base64.StdEncoding.DecodeString(b64Str)
	if err != nil {
		t.Fatalf("Get error on base64.StdEncoding.DecodeString(b64): %s", err.Error())
	}

	saltBytes, err := hex.DecodeString(salt)
	if err != nil {
		t.Fatalf("Get error on hex.DecodeString(salt): %s", err.Error())
	}

	h := hmac.New(hash, saltBytes)
	h.Write([]byte(password))

	Equal(t, h.Sum(nil), decoded, "got %s, expected %s", string(decoded), password)
}

func generateHexTest(t *testing.T, hash func() hash.Hash) {
	hexStr, salt, err := HexHash(hash, password)
	if err != nil {
		t.Fatalf("Get error on HexHash(): %s", err.Error())
	}

	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("Get error on hex.DecodeString(hex): %s", err.Error())
	}

	saltBytes, err := hex.DecodeString(salt)
	if err != nil {
		t.Fatalf("Get error on hex.DecodeString(salt): %s", err.Error())
	}

	h := hmac.New(hash, saltBytes)
	h.Write([]byte(password))

	Equal(t, h.Sum(nil), decoded, "got %s, expected %s", string(decoded), password)
}
