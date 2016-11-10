# saltissimo
[![GoDoc](https://godoc.org/github.com/golang/gddo?status.svg)](https://godoc.org/github.com/Code-Hex/saltissimo) [![Go Report Card](https://goreportcard.com/badge/github.com/Code-Hex/saltissimo)](https://goreportcard.com/report/github.com/Code-Hex/saltissimo)  
Easy generate, easy compare hash using pbkdf2.
# Why developed?
Because, It was troublesome to write code for managing customers password for each service.  
I adopted the safe pbkdf2 method as possible.  
Salt is included in the name, but what we need in this library is a secret key.
# You have used HMAC, haven't you?
Yes. I changed it because there was a security problem.  
See [reddit](https://redd.it/5c57kf).
# Synopsis
```go
func main() {
    gotFromForm := "password"
    // 1. Code to generate hash
    hash, key, err := saltissimo.HexHash(sha256.New, gotFromForm)
    if err != nil {
        panic(err)
    }
    // *Code to save some values

    // 2. Code to compare hash
    // *Code to retrieve the value from a database etc.
    // *Assume that it has already been substituted.
    isSame, err := saltissimo.CompareHexHash(sha256.New, gotFromForm, hash, key)
    if err != nil {
        panic(err)
    }
    if isSame {
        fmt.Println("Hello user!!")
    } else {
        fmt.Println("Who are you...?")
    }
}
```
# Usage
You can wrap Compare*Hash() like this
```go
func Compare(gotValue, hash, key string) bool {
    isSame, err := saltissimo.CompareHexHash(sha256.New, gotValue, hash, key)
    if err != nil {
       return false
    }
    return isSame
}
```
If you want to devise a little more, you can be happy by using these function.

```go
func PBDKF2Hex(hash func() hash.Hash, str string, key []byte) string
func PBDKF2B64(hash func() hash.Hash, str string, key []byte) string
func RandomBytes(l int) ([]byte, error)
```
Please read [GoDoc](https://godoc.org/github.com/Code-Hex/saltissimo) or [test](https://github.com/Code-Hex/saltissimo/blob/master/generate_test.go) for details.
# Get this

    go get -u github.com/Code-Hex/saltissimo

# Contribute
Please give me some PRs!!

# Author
[codehex](https://twitter.com/CodeHex)
