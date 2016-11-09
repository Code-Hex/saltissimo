package saltissimo

import (
	"encoding/hex"
	"hash"
)

func CompareHexHash(hash func() hash.Hash, str, hexStr, key string) (bool, error) {
	kb, err := hex.DecodeString(key)
	if err != nil {
		return false, err
	}
	return HmacToHex(hash, str, kb) == hexStr, err
}

func CompareB64Hash(hash func() hash.Hash, str, b64Str, key string) (bool, error) {
	kb, err := hex.DecodeString(key)
	if err != nil {
		return false, err
	}
	return HmacToB64(hash, str, kb) == b64Str, err
}
