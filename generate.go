package saltissimo

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"hash"
)

// DefaultLength specifies the length of a random byte sequence.
var DefaultLength = 36

// HexHash to generate HMAC as Hex string.
// returns HMAC, secret key, error
func HexHash(hash func() hash.Hash, str string) (string, string, error) {
	key, err := RandomBytes(DefaultLength)
	if err != nil {
		return "", "", err
	}
	return HmacToHex(hash, str, key), hex.EncodeToString(key), nil
}

// B64Hash to generate HMAC as base64 string.
// returns HMAC, secret key, error
func B64Hash(hash func() hash.Hash, str string) (string, string, error) {
	key, err := RandomBytes(DefaultLength)
	if err != nil {
		return "", "", err
	}
	return HmacToB64(hash, str, key), hex.EncodeToString(key), nil
}

// HmacToHex creates a hex string from HMAC as its name
func HmacToHex(hash func() hash.Hash, str string, key []byte) string {
	h := hmac.New(hash, key)
	h.Write([]byte(str))
	return hex.EncodeToString(h.Sum(nil))
}

// HmacToB64 creates a base64 string from HMAC as its name
func HmacToB64(hash func() hash.Hash, str string, key []byte) string {
	h := hmac.New(hash, key)
	h.Write([]byte(str))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// RandomBytes generate a random byte slice.
func RandomBytes(l int) ([]byte, error) {
	b := make([]byte, l)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
