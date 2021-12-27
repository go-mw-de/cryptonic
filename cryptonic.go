// Shared Crypto Function

package cryptonic

import (
	"crypto/rand"
	"encoding/base64"

	log "github.com/sirupsen/logrus"
)

const (
	// Chiper Type to use: aesgcm, xchaha20poly1305
	//CHIPERTYPE = "aesgcm"
	CHIPERTYPE = "xchacha20poly1305"
	// Key Derivation: simple, pbkdf2, argon2
	KDFTYPE = "pkbdf2"
)

func PWHash(pass, salt string) string {
	return base64.RawStdEncoding.EncodeToString(DeriveKey(KDFTYPE, pass, salt))
}

func PWCheck(pw, pwc, salt string) bool {
	return PWHash(pw, salt) == pwc
}

func RandomString(size int) string {
	return base64.RawStdEncoding.EncodeToString(Nonce(size))
}

func Salt(size int) string {
	return RandomString(size)
}

func Seal(plaintext, secret string) (chipertext string) {
	pt := []byte(plaintext)
	key := DeriveKey(KDFTYPE, secret, "Shared Secret, No Salt needed")
	chipertext = base64.RawStdEncoding.EncodeToString(SymmetricSeal(pt, key))
	return chipertext
}

func Open(chipertext, secret string) (plaintext string) {
	ct, err := base64.RawStdEncoding.DecodeString(chipertext)
	check(err)
	key := DeriveKey(KDFTYPE, secret, "Shared Secret, No Salt needed")
	plaintext = string(SymmetricOpen(ct, key))
	return plaintext
}

func Nonce(size int) []byte {
	nonce := make([]byte, size)
	log.Infof("nonce init:\t\t len %d / cap %d \n------------\n", len(nonce), cap(nonce))
	if _, err := rand.Read(nonce); err != nil {
		log.Fatal(err.Error())
	}
	log.Infof("nonce calc:\t\t len %d / cap %d \n------------\n", len(nonce), cap(nonce))
	return nonce
}

// sliceForAppend takes a slice and a requested number of bytes. It returns a
// slice with the contents of the given slice followed by that many bytes and a
// second slice that aliases into it and contains only the extra bytes. If the
// original slice has sufficient capacity then no allocation is performed.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

// # Helper Funtions

func check(e error) {
	if e != nil {
		log.Fatal(e)
	}
}
