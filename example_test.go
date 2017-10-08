package symcrypto_test

import (
	"fmt"

	"github.com/sudo-suhas/symcrypto"
)

func handleError(err error) {
	if err != nil {
		panic(err)
	}
}

func Example() {
	// Load your secret key from a safe place and use it to create an instance of
	// `Crypter`. (Obviously don't use this example key for anything real.) If you want
	// to convert a passphrase to a key, use a suitable package like bcrypt or scrypt.
	crypto, err := symcrypto.New("6368616e676520746869732070617373")
	handleError(err)

	// This returns the nonce appended with the encrypted string for "hello world".
	encrypted, err := crypto.Encrypt("hello world")
	handleError(err)

	// Example encrypted message - "2eUERfII6K7djr-GCR2qwSf8LJ-7ZoOmdlT54HPkhw297ML46M6VvlpvW2LrA_Ewge-2"
	// Because of unique nonce, encrypted message will vary for the same input.

	// The encrypted string can be decrypted only by using the `Crypter` instance which
	// was used to encrypt it.
	decrypted, err := crypto.Decrypt(encrypted)
	handleError(err)

	fmt.Printf("Decrypted message - %q\n", decrypted)
	// Output: Decrypted message - "hello world"
}
