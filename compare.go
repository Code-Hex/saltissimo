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
	"encoding/hex"
	"hash"
)

// CompareHexHash to compare passed string and HMAC as hex string.
func CompareHexHash(hash func() hash.Hash, str, hexStr, key string) (bool, error) {
	kb, err := hex.DecodeString(key)
	if err != nil {
		return false, err
	}
	return HmacToHex(hash, str, kb) == hexStr, err
}

// CompareB64Hash to compare passed string and HMAC as base64 string.
func CompareB64Hash(hash func() hash.Hash, str, b64Str, key string) (bool, error) {
	kb, err := hex.DecodeString(key)
	if err != nil {
		return false, err
	}
	return HmacToB64(hash, str, kb) == b64Str, err
}
