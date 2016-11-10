package saltissimo

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"hash"

	"golang.org/x/crypto/pbkdf2"
)

// SaltLength specifies the length of a random byte sequence.
var (
	KeyLength  = 32
	SaltLength = 36
	Iter       = 4096
)

// HexHash to generate PBDKF2 as Hex string.
// returns PBDKF2, secret key, error
func HexHash(hash func() hash.Hash, str string) (string, string, error) {
	key, err := RandomBytes(SaltLength)
	if err != nil {
		return "", "", err
	}
	return PBDKF2Hex(hash, str, key), hex.EncodeToString(key), nil
}

// B64Hash to generate PBDKF2 as base64 string.
// returns PBDKF2, secret key, error
func B64Hash(hash func() hash.Hash, str string) (string, string, error) {
	key, err := RandomBytes(SaltLength)
	if err != nil {
		return "", "", err
	}
	return PBDKF2B64(hash, str, key), hex.EncodeToString(key), nil
}

// PBDKF2Hex creates a hex string from PBDKF2 as its name
func PBDKF2Hex(hash func() hash.Hash, str string, key []byte) string {
	b := pbkdf2.Key([]byte(str), key, Iter, KeyLength, hash)
	return hex.EncodeToString(b)
}

// PBDKF2B64 creates a base64 string from PBDKF2 as its name
func PBDKF2B64(hash func() hash.Hash, str string, key []byte) string {
	b := pbkdf2.Key([]byte(str), key, Iter, KeyLength, hash)
	return base64.StdEncoding.EncodeToString(b)
}

// RandomBytes generate a random byte slice.
func RandomBytes(l int) ([]byte, error) {
	b := make([]byte, l)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
