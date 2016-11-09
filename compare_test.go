package saltissimo

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCompareSHA1(t *testing.T) {
	compareHexTest(t, sha1.New)
	compareB64Test(t, sha1.New)
}

func TestCompareSHA256(t *testing.T) {
	compareHexTest(t, sha256.New)
	compareB64Test(t, sha256.New)
}

func TestCompareSHA512(t *testing.T) {
	compareHexTest(t, sha512.New)
	compareB64Test(t, sha512.New)
}

func compareHexTest(t *testing.T, hash func() hash.Hash) {
	hex, salt, err := HexHash(hash, password)
	if err != nil {
		t.Fatalf("Get error on HmacHex(): %s", err.Error())
	}
	got, err := CompareHexHash(hash, password, hex, salt)
	if err != nil {
		t.Fatalf("Get error on CompareHexHash(): %s", err.Error())
	}

	Equal(t, true, got, "got %t, expected %t", got, true)
}

func compareB64Test(t *testing.T, hash func() hash.Hash) {
	b64, salt, err := B64Hash(hash, password)
	if err != nil {
		t.Fatalf("Get error on HmacB64(): %s", err.Error())
	}

	got, err := CompareB64Hash(hash, password, b64, salt)
	if err != nil {
		t.Fatalf("Get error on CompareB64Hash(): %s", err.Error())
	}
	Equal(t, true, got, "got %t, expected %t", got, true)
}

func Equal(t *testing.T, expected interface{}, actual interface{}, format string, args ...interface{}) {
	assert.Equal(t, expected, actual, fmt.Sprintf(format, args...))
}
