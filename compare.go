// Package saltissimo was developed to easily compare hash of salt password.
// Suppose you have saved like this data.
//
//  +--------------------------+
//  | PBDKF2_hex  | secret_key |
//  +--------------------------+
//  | 5f54e622... | 951ff34... |
//  +--------------------------+
//
// Then, you are passed any string. Assume that you are given a "password" here.
// You can use compare function looks like this:
//  saltissimo.CompareHexHash(sha256.New, "password", PBDKF2_hexstr, secret_key)
package saltissimo

import (
	"encoding/base64"
	"encoding/hex"

	"golang.org/x/crypto/pbkdf2"

	"hash"
)

// CompareHexHash to compare passed string and PBDKF2 as hex string.
func CompareHexHash(hash func() hash.Hash, str, hexStr, key string) (bool, error) {
	kb, err := hex.DecodeString(key)
	if err != nil {
		return false, err
	}

	orig, err := hex.DecodeString(hexStr)
	if err != nil {
		return false, err
	}

	sum := pbkdf2.Key([]byte(str), kb, Iter, KeyLength, hash)
	return compare(sum, orig), nil
}

// CompareB64Hash to compare passed string and PBDKF2 as base64 string.
func CompareB64Hash(hash func() hash.Hash, str, b64Str, key string) (bool, error) {
	kb, err := hex.DecodeString(key)
	if err != nil {
		return false, err
	}

	orig, err := base64.StdEncoding.DecodeString(b64Str)
	if err != nil {
		return false, err
	}

	sum := pbkdf2.Key([]byte(str), kb, Iter, KeyLength, hash)
	return compare(sum, orig), nil
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
