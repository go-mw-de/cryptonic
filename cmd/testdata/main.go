package main

import (
	"encoding/base64"
	"fmt"

	"go-mw.de/pkg/cryptonic"
)

func main() {
	t := []string{"pkbdf2", "argon2i", "argon2id"}

	//	decode := base64.RawStdEncoding.DecodeString
	encode := base64.RawStdEncoding.EncodeToString
	salt := "IFKaEo/lCHkwdGaa+KUpJg"
	pass := "bH/Kj/wXOd3wpLxSjwDVbw"
	fmt.Println("pass", pass, "salt", salt)
	for _, v := range t {
		fmt.Println(v, encode(cryptonic.DeriveKey(v, pass, salt)))
	}
}
