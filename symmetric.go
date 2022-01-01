// # Symmetric

package cryptonic

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/chacha20poly1305"
)

// Use AEAD Terminology Seal == Encrypte and Open == Decrypt
func SymmetricSeal(plaintext, key []byte) []byte {
	return Encrypt(CHIPERTYPE, key, plaintext)
}

func SymmetricOpen(chipertext, key []byte) []byte {
	return Decrypt(CHIPERTYPE, key, chipertext)
}

func Encrypt(chiper string, key, msg []byte) []byte {
	switch t := chiper; t {
	case "aesgcm":
		return AESEncrypt(key, msg)
	case "xchacha20poly1305":
		return XCPEncrypt(key, msg)
	default:
		log.Fatalf("crypto Type '%s' is not supported", t)
		return nil
	}
}

func Decrypt(chiper string, key, msg []byte) []byte {
	switch t := chiper; t {
	case "aesgcm":
		return AESDecrypt(key, msg)
	case "xchacha20poly1305":
		return XCPDecrypt(key, msg)
	default:
		err := fmt.Errorf("chiper type '%s' is not supported", t)
		panic(err)
	}
}

func AESEncrypt(key, msg []byte) []byte {
	block, err := aes.NewCipher(key)
	check(err)
	aead, err := cipher.NewGCM(block)
	check(err)

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := Nonce(aead.NonceSize())
	// First Argument to Seal send nonce to destination (dst) or in otherwords nonce will be appended
	return aead.Seal(nonce, nonce, msg, nil)

}

func AESDecrypt(key, msg []byte) []byte {
	block, err := aes.NewCipher(key)
	check(err)
	aead, err := cipher.NewGCM(block)
	check(err)

	// split ct in nonce and data
	nonce := msg[:aead.NonceSize()]
	ct := msg[aead.NonceSize():]
	pt, err := aead.Open(nil, nonce, ct, nil)
	check(err)

	return pt
}

// ## XChacha20poly1305
func XCPEncrypt(key, msg []byte) []byte {
	aead, err := chacha20poly1305.NewX(key)
	check(err)
	// Select a random nonce, and leave capacity for the ciphertext.
	nonce := Nonce(aead.NonceSize())
	// First Argument to Seal send nonce to destination (dst) or in otherwords nonce will be appended
	return aead.Seal(nonce, nonce, msg, nil)

}

func XCPDecrypt(key, msg []byte) []byte {
	aead, err := chacha20poly1305.NewX(key)
	check(err)

	// split ct in nonce and data
	nonce := msg[:aead.NonceSize()]
	ct := msg[aead.NonceSize():]
	pt, err := aead.Open(nil, nonce, ct, nil)
	check(err)

	return pt
}
