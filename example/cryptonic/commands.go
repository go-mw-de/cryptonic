// All Command

package main

import (
	"bytes"
	"fmt"
	"strings"
	"sync"

	. "gitlab.com/echtwerner/cryptonic"
)

// # Main Programm Functions
func genKey(filebasename string, keysize int, passphrase string) {
	testPT := []byte("This string is to Test if key generation was successfull")
	fmt.Printf("testPT:\t %q\n------------\n", testPT)
	priv, pub := RSAGenKeyPair(keysize)
	fmt.Printf("Privatekey:\t %#v\n------------\n", priv)
	fmt.Printf("Publickey:\t %#v\n------------\n", pub)

	RSAWriteKeyPair(filebasename, priv, pub, passphrase)

	fmt.Printf("### Reload Keys\n------------\n")
	priv2, pub2 := RSAReadKeyPair(filebasename, passphrase)
	fmt.Printf("Reload Privatekey:\t %#v\n------------\n", priv2)
	fmt.Printf("Reload Publickey:\t %#v\n------------\n", pub2)

	fmt.Printf("### Start Test\n------------\n")
	testCT := RSAEncrypt(pub, testPT)
	fmt.Printf("testCT:\t %x\n------------\n", testCT)
	testPT2 := RSADencrypt(priv, testCT)
	fmt.Printf("testPT2:\t %s\n------------\n", testPT2)
	if !bytes.Equal(testPT, testPT2) {
		panic("### FAILED ### RSA Key Generation was not successfull\n------------\n")
	}
	fmt.Printf("### SUCCESSFUL ### RSA keys generated succussfull \n------------\n")
}

func reGenPubkey(filebasename string, passphrase string) {
	RSARenGenPubKey(filebasename, passphrase)
	fmt.Println("RSA Public key regenerated successfull‚")
}

func encryptMessage(wg *sync.WaitGroup, filebasename, plaintext, passphrase string, c chan<- []byte) {
	defer wg.Done()
	pt := []byte(plaintext)
	fmt.Printf("encryptMessage pt:\t\t %q\n------------\n", pt)
	fn := strings.Join([]string{filebasename, "pub", "json"}, ".")
	pk := RSAReadPublicKey(fn)
	//fmt.Printf("publickey:\t\t %x\n------------\n", pk)
	key := KeyDerive(passphrase)
	fmt.Printf("encryptMessage key:\t\t %x\n------------\n", key)
	// Send Key over the channel
	ck := AsymmetricEncrypt(key, pk)
	fmt.Printf("encryptMessage aenc-key:\t %x\n------------\n", ck)
	c <- ck
	// Send Chipertext over the channel
	ct := SymmetricSeal(pt, key)
	fmt.Printf("encryptMessage ct:\t\t %x\n------------\n", ct)
	c <- ct
}

func decryptMessage(wg *sync.WaitGroup, filebasename, passphrase string, c <-chan []byte) {
	defer wg.Done()
	fPrivName := strings.Join([]string{filebasename, "json"}, ".")
	sk := RSAReadEncryptedPrivateKey(fPrivName, passphrase)
	// Receive Key from channel
	key := AsymmetricDecrypt(<-c, sk)
	fmt.Printf("decryptMessage key:\t\t %x\n------------\n", key)
	pt := SymmetricOpen(<-c, key)
	fmt.Printf("decryptMessage pt:\t\t %q\n------------\n", pt)
}

func signMessage(wg *sync.WaitGroup, filebasename, message, passphrase string, c chan<- []byte) {
	defer wg.Done()
	fPrivName := strings.Join([]string{filebasename, "json"}, ".")
	sk := RSAReadEncryptedPrivateKey(fPrivName, passphrase)
	msg := []byte(message)
	fmt.Printf("signMessage msg:\t\t %q\n------------\n", msg)
	c <- msg
	sig := AsymmetricSign(msg, sk)
	fmt.Printf("signMessage sig:\t\t %x\n------------\n", sig)
	c <- sig

}

func verifyMessage(wg *sync.WaitGroup, filebasename string, c <-chan []byte) {
	defer wg.Done()
	fn := strings.Join([]string{filebasename, "pub", "json"}, ".")
	pk := RSAReadPublicKey(fn)
	msg := <-c
	fmt.Printf("verifyMessage msg:\t\t %q\n------------\n", msg)
	sig := <-c
	fmt.Printf("verifyMessage sig:\t\t %x\n------------\n", sig)
	if AsymmetricVerify(msg, pk, sig) {
		fmt.Printf("### SUCCESSFUL ### Signature verified\n------------\n")
	} else {

		fmt.Printf("### FAILED ### Signature false\n------------\n")
	}
}

func deriveKeys(passphrase string) {
	p := []byte(passphrase)
	s := []byte(Salt(16))
	fmt.Printf("Passphrase:\t\t %q\n------------\n", p)
	fmt.Printf("Salt:\t\t %x\n------------\n", s)
	fmt.Printf("PKBDF2:\t\t %x\n------------\n", PKBDF2DeriveKey(p, s))
	fmt.Printf("Argon2i:\t %x\n------------\n", Argon2iDeriveKey(p, s))
	fmt.Printf("Argon2id:\t %x\n------------\n", Argon2idDeriveKey(p, s))

}
