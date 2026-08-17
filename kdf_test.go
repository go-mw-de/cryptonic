package cryptonic_test

import (
	"encoding/base64"
	"testing"

	"github.com/matryer/is"
	"github.com/go-mw-de/cryptonic"
)

var kdfTypes = []string{"pkbdf2", "argon2i", "argon2id"}

var testData = map[string]string{
	"pass":     "bH/Kj/wXOd3wpLxSjwDVbw",
	"salt":     "IFKaEo/lCHkwdGaa+KUpJg",
	"pkbdf2":   "R9NQ5n9+e6oPNCxK0ZJtG0A/FqmjAxmlToQWXhfxzJE",
	"argon2i":  "70dswc5MwPx8QIYp3HX2wQibBrVoKB3nTADGycFHcdc",
	"argon2id": "m1tr+1puYSrnXrFRNFsWFAm/1259tDNOgQKVfrXyp94",
}

func decode(s string) (bytes []byte) {
	bytes, err := base64.RawStdEncoding.DecodeString(s)
	check(err)
	return bytes
}

func TestDeriveKey(t *testing.T) {
	is := is.New(t)
	for _, v := range kdfTypes {
		is.Equal(cryptonic.DeriveKey(v, testData["pass"], testData["salt"]), decode(testData[v]))
	}
}

func TestArgon2iDeriveKey(t *testing.T) {
	is := is.New(t)
	p := []byte(testData["pass"])
	s := []byte(testData["salt"])
	is.Equal(cryptonic.Argon2iDeriveKey(p, s), decode(testData["argon2i"]))
}

func TestArgon2idDeriveKey(t *testing.T) {
	is := is.New(t)
	p := []byte(testData["pass"])
	s := []byte(testData["salt"])
	is.Equal(cryptonic.Argon2idDeriveKey(p, s), decode(testData["argon2id"]))
}

func TestPKBDF2DeriveKey(t *testing.T) {
	is := is.New(t)
	p := []byte(testData["pass"])
	s := []byte(testData["salt"])
	is.Equal(cryptonic.PKBDF2DeriveKey(p, s), decode(testData["pkbdf2"]))
}
