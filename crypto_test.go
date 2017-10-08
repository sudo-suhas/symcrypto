package symcrypto

import (
	"fmt"
	"testing"
)

func getCrypto(t *testing.T, secret string) Crypter {
	crypto, err := New(secret)

	if err != nil {
		t.Fatalf("could not create an instance of Crypter: %+v\n", err)
	}

	return crypto
}

func defCrypto(t *testing.T) Crypter {
	return getCrypto(t, "secret_key_with_string_length_32")
}

func TestGetMidBytes(t *testing.T) {
	// Invalid input tests
	errCases := []struct {
		name    string
		size    int
		wantErr string
	}{
		{"size 0", 0, "expected size to be at least 1, got 0"},
		{"size -1", -1, "expected size to be at least 1, got -1"},
		{"len(bytes) < size", 10, "expected bytes length to be at least 10, got 3"},
	}

	for _, c := range errCases {
		t.Run("err/"+c.name, func(t *testing.T) {
			_, err := getMidBytes([]byte("abc"), c.size)
			if err == nil || err.Error() != c.wantErr {
				t.Errorf("expected error %q, got %q", c.wantErr, err)
			}
		})
	}

	// Valid input tests
	cases := []struct {
		name      string
		size      int
		str, want string
	}{
		// len(input) == size ➡ input
		{"len(input)=size", 5, "abcde", "abcde"},
		// len(input) == size+1 ➡ input[1:]
		{"len(input)=size+1", 5, "abcdef", "bcdef"},
		// len(input) == size+2 ➡ input[1 : len(input)-1]
		{"len(input)=size+2", 4, "abcdef", "bcde"},
		// len(input) == size+3 ➡ input[2 : len(input)-1]
		{"len(input)=size+3", 3, "abcdef", "cde"},
		// len(input) == size+4 ➡ input[2 : len(input)-2]
		{"len(input)=size+4", 3, "abcdefg", "cde"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mid, err := getMidBytes([]byte(c.str), c.size)

			if err != nil {
				t.Fatalf("unexpected error: %+v", err)
			}

			got := string(mid)
			if got != c.want {
				t.Errorf("expected %q, got %q\n", c.want, got)
			}
		})
	}
}

func TestNew(t *testing.T) {
	t.Run("initialise with short or empty key", func(t *testing.T) {
		// Test for initialisation with empty/short secret key
		wantErr := "invalid secret key: expected bytes length to be at least 32, got 0"
		_, err := New("")
		if err == nil || err.Error() != wantErr {
			t.Errorf("expected error %q, got %q", wantErr, err)
		}
	})

	t.Run("different secrets with same first 32 chars", func(t *testing.T) {
		// Test for initialisation with secret key having first 32 chars same. The Crypter
		// created with the longer key should omit some characters from the start to ensure
		// that the secret key is not the same.
		c1 := defCrypto(t)
		c2 := getCrypto(t, "secret_key_with_string_length_32_and_then_some")

		if c1.(*crypter).secretKey == c2.(*crypter).secretKey {
			t.Error("expected secret keys to be different even if first 32 chars are the same")
		}
	})
}

func TestEncrypt(t *testing.T) {
	msg := "hello world"
	set := make(map[string]bool, 100)
	crypto := defCrypto(t)

	ctr, threshold := 0, 10
	for i := 0; i < 10000; i++ {
		encrypted, err := crypto.Encrypt(msg)

		if err != nil {
			t.Fatalf("unexpected err from encrypt string %q: %+v\n", msg, err)
		}

		if set[encrypted] {
			fmt.Printf("unexpected repetition of encrypted token: %q\n", encrypted)
			ctr++

			if ctr >= threshold {
				t.Fatalf("encrypted token repetition exceeded threshold %d", threshold)
			}
		} else {
			set[encrypted] = true
		}
	}
}

func TestDecrypt(t *testing.T) {
	crypto := defCrypto(t)

	errCases := []struct {
		name, msg, wantErr string
	}{
		{"illegal base64", "/", `failed to decode "/" using base64: illegal base64 data at input byte 0`},
		{"invalid(empty) encrypted msg", "", `invalid encrypted message, "" is too short`},
		{
			"arbitrary string",
			"some_string_which_was_not_encrypted_using_symcrypto",
			`failed to decrypt "some_string_which_was_not_encrypted_using_symcrypto"`,
		},
	}

	for _, c := range errCases {
		t.Run("err/"+c.name, func(t *testing.T) {
			_, err := crypto.Decrypt(c.msg)
			if err == nil || err.Error() != c.wantErr {
				t.Errorf("expected error %q, got %q", c.wantErr, err)
			}
		})
	}
}

func TestE2E(t *testing.T) {
	crypto := defCrypto(t)

	trojan := getCrypto(t, "some_other_different_secret_key_")

	msgs := []string{"", "hello world", "⮕😃⬅", "123456"}

	for _, msg := range msgs {
		t.Run(fmt.Sprintf("encrypt %q", msg), func(t *testing.T) {
			encrypted, err := crypto.Encrypt(msg)

			if err != nil {
				t.Fatalf("unexpected err from encrypt string %q: %+v\n", msg, err)
			}

			decrypted, err := crypto.Decrypt(encrypted)

			if err != nil {
				t.Fatalf("unexpected err from decrypt string %q: %+v\n", encrypted, err)
			}

			if decrypted != msg {
				t.Errorf("expected decrypted string to be %q, got %q\n", msg, decrypted)
			}

			_, err = trojan.Decrypt(encrypted)

			wantErr := fmt.Sprintf("failed to decrypt %q", encrypted)
			if err == nil || err.Error() != wantErr {
				t.Errorf("expected error %q, got %q", wantErr, err)
			}
		})
	}
}
