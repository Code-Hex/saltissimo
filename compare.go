// Package saltissimo was developed to easily compare hash of salt password.
// Suppose you have saved like this data.
//
//  +--------------------------+
//  | HMAC_hexstr | secret_key |
//  +--------------------------+
//  | 5f54e622... | 951ff34... |
//  +--------------------------+
//
// Then, you are passed any string. Assume that you are given a "password" here.
// You can use compare function looks like this:
//  saltissimo.CompareHexHash(sha256.New, "password", HMAC_hexstr, secret_key)
package saltissimo

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/hex"

	"hash"
)

// CompareHexHash to compare passed string and HMAC as hex string.
func CompareHexHash(hash func() hash.Hash, str, hexStr, key string) (bool, error) {
	kb, err := hex.DecodeString(key)
	if err != nil {
		return false, err
	}

	orig, err := hex.DecodeString(hexStr)
	if err != nil {
		return false, err
	}

	h := hmac.New(hash, kb)
	h.Write([]byte(str))
	return compare(h.Sum(nil), orig), nil
}

// CompareB64Hash to compare passed string and HMAC as base64 string.
func CompareB64Hash(hash func() hash.Hash, str, b64Str, key string) (bool, error) {
	kb, err := hex.DecodeString(key)
	if err != nil {
		return false, err
	}

	orig, err := base64.StdEncoding.DecodeString(b64Str)
	if err != nil {
		return false, err
	}

	h := hmac.New(hash, kb)
	h.Write([]byte(str))
	return compare(h.Sum(nil), orig), nil
}

func compare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}

	return result == 0
}
