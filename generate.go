package saltissimo

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"hash"
)

var DefaultLength = 36

func HexHash(hash func() hash.Hash, str string) (string, string, error) {
	key, err := RandomBytes(DefaultLength)
	if err != nil {
		return "", "", err
	}
	return HmacToHex(hash, str, key), hex.EncodeToString(key), nil
}

func B64Hash(hash func() hash.Hash, str string) (string, string, error) {
	key, err := RandomBytes(DefaultLength)
	if err != nil {
		return "", "", err
	}
	return HmacToB64(hash, str, key), hex.EncodeToString(key), nil
}

func HmacToHex(hash func() hash.Hash, str string, key []byte) string {
	h := hmac.New(hash, key)
	h.Write([]byte(str))
	return hex.EncodeToString(h.Sum(nil))
}

func HmacToB64(hash func() hash.Hash, str string, key []byte) string {
	h := hmac.New(hash, key)
	h.Write([]byte(str))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func RandomBytes(l int) ([]byte, error) {
	b := make([]byte, l)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
