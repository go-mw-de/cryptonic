// # Key Derivation Function

package cryptonic

import (
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

// Simple API
func KeyDerive(passphrase string) []byte {
	return DeriveKey(KDFTYPE, passphrase, Salt(16))
}

// Derive Key Main Function
func DeriveKey(derivetype, passphrase, salt string) []byte {
	p := []byte(passphrase)
	s := []byte(salt)
	switch t := derivetype; t {
	case "pkbdf2":
		return PKBDF2DeriveKey(p, s)
	case "argon2i":
		return Argon2iDeriveKey(p, s)
	case "argon2id":
		return Argon2idDeriveKey(p, s)
	default:
		err := fmt.Errorf("derive key type '%s' is not supported", t)
		panic(err)
	}
}

// Argon2i
func Argon2iDeriveKey(p, s []byte) []byte {
	return argon2.Key(p, s, 5, 256*1024, 4, 32)
}

// Argon2id
func Argon2idDeriveKey(p, s []byte) []byte {
	return argon2.IDKey(p, s, 2, 512*1024, 4, 32)
}

// ### PKBDF2
func PKBDF2DeriveKey(p, s []byte) []byte {
	return pbkdf2.Key(p, s, 100000, 32, sha256.New)
}
