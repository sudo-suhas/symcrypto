/*
Package symcrypto is a URL safe encryption/decryption library.

It uses golang.org/x/crypto/nacl/secretbox under the hood which is suitable for
encrypting small messages. "encoding/base64" is used to make the encrypted token URL
safe.
*/
package symcrypto // import "github.com/sudo-suhas/symcrypto"

import (
	"crypto/rand"
	"encoding/base64"

	"github.com/pkg/errors"
	"golang.org/x/crypto/nacl/secretbox"
)

// SecretKeyLen is the minimum length of secret key required for creating an instance of
// Crypter. NaCl expects the secret key to be 32 characters long.
const SecretKeyLen = 32

const nonceLen = 24

var encoding = base64.RawURLEncoding

// Crypter does encryption and decription using the given secret key. The encrypted
// string is URL safe via base64 encoding.
type Crypter interface {
	// Encrypt encrypts the given message using the configured secret key and returns the
	// encrypted string. The encrypted string is encoded using base64 so that it can be
	// used in the URL.
	Encrypt(string) (string, error)

	// Decrypt decrypts and returns the given token using the configured secret key. The
	// encrypted string is expected to be base64 encoded.
	Decrypt(string) (string, error)
}

// crypter is a private struct which implements the interface. It can only be
// instantiated via the `New` function.
type crypter struct {
	secretKey [32]byte
}

/*
	It is possible in Go land for the pointer receiver in `Encrypt` and `Decrypt` to be
	`nil`. However, for this, the user would have to assign a uninitialised `nil` pointer
	to the `Crypter` interface variable. Since our struct is private, this will not be
	possible.

	Refer:
	 - 'Interface values with nil underlying values' - https://tour.golang.org/methods/12
	 - 'Nil interface values' - https://tour.golang.org/methods/13
*/

func (c *crypter) Encrypt(msg string) (string, error) {
	// Use a different nonce for each message encrypted with the same key. Since the
	// nonce here is 192 bits long, a random value provides a sufficiently small
	// probability of repeats.
	var nonce [nonceLen]byte

	if _, err := rand.Reader.Read(nonce[:]); err != nil {
		// We don't really expect this to happen.
		return "", errors.Wrap(err, "failed to generate nonce")
	}

	// This encrypts the message and appends the result to the nonce.
	encrypted := secretbox.Seal(nonce[:], []byte(msg), &nonce, &c.secretKey)

	// We encode the encrypted string because we want to be able to use it in a URL.
	return encoding.EncodeToString(encrypted), nil
}

func (c *crypter) Decrypt(msg string) (string, error) {
	// First we decode the encrypted message using base64 because that was the last step
	// of encryption.
	crypticBytes, err := encoding.DecodeString(msg)

	if err != nil {
		return "", errors.Wrapf(err, "failed to decode %q using base64", msg)
	}
	if len(crypticBytes) <= nonceLen {
		// The encrypted message can't possibly be shorter than 24 chars which is
		// supposed to be just the nonce! By doing this check, we also avoid a panic:
		// panic: runtime error: slice bounds out of range
		return "", errors.Errorf("invalid encrypted message, %q is too short", msg)
	}

	// When we decrypt, we must use the same nonce and key we used to encrypt the
	// message. One way to achieve this is to store the nonce alongside the encrypted
	// message. Above, we stored the nonce in the first 24 bytes of the encrypted text.
	var nonce [nonceLen]byte
	copy(nonce[:], crypticBytes[:nonceLen])

	decrypted, ok := secretbox.Open(nil, crypticBytes[nonceLen:], &nonce, &c.secretKey)

	if !ok {
		return "", errors.Errorf("failed to decrypt %q", msg)
	}

	return string(decrypted), nil
}

func errInput(name string, expected, got int) error {
	return errors.Errorf(
		"expected %s to be at least %d, got %d",
		name, expected, got,
	)
}

func getMidBytes(bytes []byte, size int) ([]byte, error) {
	if size <= 0 {
		return nil, errInput("size", 1, size)
	}

	bytesLen := len(bytes)
	if bytesLen < size {
		return nil, errInput("bytes length", size, bytesLen)
	}

	startIdx := (bytesLen - size + 1) / 2
	return bytes[startIdx : startIdx+size], nil
}

// New creates an instance of Crypter which can be used for encrypting/decrypting with
// the same secret key.
//
// It is recommedded to load your secret key from a safe place and use it for
// instantiating a Crypter instance. If you want to convert a passphrase to a key, use a
// suitable package like bcrypt or scrypt. The secret key must be at least 32 chars long.
// If the length exceeds 32 chars, the mid 32 chars will be used as the secret key.
func New(secret string) (Crypter, error) {
	// See https://godoc.org/golang.org/x/crypto/nacl/secretbox
	// Take the middle 32 bytes from given secret key.
	secretKeyBytes, err := getMidBytes([]byte(secret), SecretKeyLen)

	if err != nil {
		return nil, errors.Wrap(err, "invalid secret key")
	}

	var secretKey [SecretKeyLen]byte
	copy(secretKey[:], secretKeyBytes)
	return &crypter{secretKey}, nil
}
