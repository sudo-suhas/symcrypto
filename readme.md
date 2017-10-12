# symcrypto

[![Build Status](https://travis-ci.org/sudo-suhas/symcrypto.svg?branch=master)](https://travis-ci.org/sudo-suhas/symcrypto)
[![Coverage Status](https://coveralls.io/repos/github/sudo-suhas/symcrypto/badge.svg?branch=master)](https://coveralls.io/github/sudo-suhas/symcrypto?branch=master)
[![GoDoc](https://godoc.org/github.com/sudo-suhas/symcrypto?status.svg)](https://godoc.org/github.com/sudo-suhas/symcrypto)
[![Go Report Card](https://goreportcard.com/badge/github.com/sudo-suhas/symcrypto)](https://goreportcard.com/report/github.com/sudo-suhas/symcrypto)

> A URL safe, string encryption/decryption library.

Encryption and decryption is done using a secret key.
[`secretbox`](https://godoc.org/golang.org/x/crypto/nacl/secretbox) is used under the hood.

## Install

```
# using dep(recommended)
$ dep ensure -add github.com/sudo-suhas/symcrypto

# using go get
$ go get -u github.com/sudo-suhas/symcrypto
```

## Usage

```go
package main

import (
	"fmt"

	"github.com/sudo-suhas/symcrypto"
)

func handleError(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	// Load your secret key from a safe place and use it to create an instance of
	// `Crypter`. (Obviously don't use this example key for anything real.) If you want
	// to convert a passphrase to a key, use a suitable package like bcrypt or scrypt.
	crypto, err := symcrypto.New("6368616e676520746869732070617373")
	handleError(err)

	// This returns the nonce appended with the encrypted string for "hello world".
	encrypted, err := crypto.Encrypt("hello world")
	handleError(err)

	fmt.Printf("Encrypted message - %q\n", encrypted)
	// Output: Encrypted message - "2eUERfII6K7djr-GCR2qwSf8LJ-7ZoOmdlT54HPkhw297ML46M6VvlpvW2LrA_Ewge-2"
	// Because of unique nonce, encrypted message will vary for the same input.

	// The encrypted string can be decrypted only by using the `Crypter` instance which
	// was used to encrypt it.
	decrypted, err := crypto.Decrypt(encrypted)
	handleError(err)

	fmt.Printf("Decrypted message - %q\n", decrypted)
	// Output: Decrypted message - "hello world"
}

```

## License

MIT © [Suhas Karanth](https://github.com/sudo-suhas)
