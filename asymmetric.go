// # Asymmetric

package cryptonic

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

const (
	// SHA256
	AsymmetricHashSumSize = 32
)

// Authenticated Public-Key Encryption

// Currently not implemented
func AsymmetricSeal(plaintext []byte, pk *rsa.PublicKey, sk *rsa.PrivateKey) []byte {
	//pkr := *pk
	//pkrsa := pkr.(rsa.PublicKey)
	return RSAEncrypt(pk, plaintext)
}

// Currently not implemented
func AsymmetricOpen(chipertext []byte, sk *rsa.PrivateKey, pk *rsa.PublicKey) []byte {
	//skr := *pk
	//skrsa := skr.(rsa.PrivateKey)
	return RSADencrypt(sk, chipertext)
}

// Anonymous Public-Key Encryption
func AsymmetricEncrypt(plaintext []byte, pk *rsa.PublicKey) []byte {
	//pkr := *pk
	//pkrsa := pkr.(rsa.PublicKey)
	return RSAEncrypt(pk, plaintext)
}

func AsymmetricDecrypt(chipertext []byte, sk *rsa.PrivateKey) []byte {
	//skr := *pk
	//skrsa := skr.(rsa.PrivateKey)
	return RSADencrypt(sk, chipertext)
}

// AsymmetricSign return a byte stream with hashsum and signature concat
func AsymmetricSign(message []byte, sk *rsa.PrivateKey) []byte {
	msg := []byte(message)
	hsum, sig := RSASign(sk, msg)
	if len(hsum) != AsymmetricHashSumSize {
		panic("Hashsum Length does not match AsymmetricHashSumSize")
	}
	fmt.Printf("AsymmetricSign sig:\t\t %x\n------------\n", sig)
	fmt.Printf("AsymmetricSign hash:\t\t %x\n------------\n", hsum)
	sig2, out := sliceForAppend(hsum, len(sig))
	fmt.Printf("AsymmetricSign out:\t %x\n------------\n", out)
	fmt.Printf("AsymmetricSign sig2:\t %x\n------------\n", sig2)
	copy(out, sig)
	fmt.Printf("AsymmetricSign out:\t %x\n------------\n", out)
	fmt.Printf("AsymmetricSign sig2:\t %x\n------------\n", sig2)
	ret := make([]byte, len(sig)+AsymmetricHashSumSize)
	copy(ret, sig2)
	fmt.Printf("AsymmetricSign ret:\t %x\n------------\n", ret)

	return ret
}

func AsymmetricSignWithHash(message []byte, sk *rsa.PrivateKey) ([]byte, []byte) {
	msg := []byte(message)
	hsum, sig := RSASign(sk, msg)
	if len(hsum) != AsymmetricHashSumSize {
		panic("Hashsum Length does not match AsymmetricHashSumSize")
	}
	return sig, hsum
}

func AsymmetricVerify(message []byte, pk *rsa.PublicKey, signature []byte) bool {
	hsum := signature[:AsymmetricHashSumSize]
	sig := signature[AsymmetricHashSumSize:]
	fmt.Printf("AsymmetricVerify sig:\t\t %x\n------------\n", sig)
	fmt.Printf("AsymmetricVerify hash:\t\t %x\n------------\n", hsum)

	return RSAVerify(pk, hsum, sig)
}

func AsymmetricVerifyWithHash(message []byte, pk *rsa.PublicKey, signature, hash []byte) bool {
	hsum := hash
	sig := signature
	return RSAVerify(pk, hsum, sig)
}

// # RSA

type RSAEncryptedPrivateKey struct {
	Chiper     string
	KDF        string
	Salt       string
	Privatekey []byte
}

// ### RSA En-/Decription
func RSAEncrypt(key *rsa.PublicKey, msg []byte) []byte {
	data, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		key,
		msg,
		nil)
	check(err)
	return data
}

func RSADencrypt(key *rsa.PrivateKey, msg []byte) []byte {
	// Use key Method()
	// data, err := key.Decrypt(nil, text, &rsa.OAEPOptions{Hash: crypto.SHA256})
	// Use package Level Function()
	data, err := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		key,
		msg,
		nil)
	check(err)
	return data
}

// ### RSA Sign and Verify
func RSASign(key *rsa.PrivateKey, msg []byte) (msgHashSum, sig []byte) {
	// Before signing, we need to hash our message
	// The hash is what we actually sign
	msgHash := sha256.New()
	_, err := msgHash.Write(msg)
	check(err)

	msgHashSum = msgHash.Sum(nil)

	// In order to generate the signature, we provide a random number generator,
	// our private key, the hashing algorithm that we used, and the hash sum
	// of our message
	sig, err = rsa.SignPSS(rand.Reader, key, crypto.SHA256, msgHashSum, nil)
	check(err)
	return msgHashSum, sig
}

func RSAVerify(key *rsa.PublicKey, msgHashSum, sig []byte) bool {

	// To verify the signature, we provide the public key, the hashing algorithm
	// the hash sum of our message and the signature we generated previously
	// there is an optional "options" parameter which can omit for now
	err := rsa.VerifyPSS(key, crypto.SHA256, msgHashSum, sig, nil)
	if err != nil {
		return false
	}
	// If we don't get any error from the `VerifyPSS` method, that means our
	// signature is valid
	return true

}

// ### RSA Keyhandling

func RSAGenKeyPair(keySize int) (*rsa.PrivateKey, *rsa.PublicKey) {
	// The GenerateKey method takes in a reader that returns random bits, and
	// the number of bits
	priv, err := rsa.GenerateKey(rand.Reader, keySize)
	check(err)
	pub := &priv.PublicKey
	return priv, pub
}

// #ISSUE if you your privkey is encrypted and you regen pub key with option uncrypted this leads to an empty pubkey
// Won't fix cause no data loose and you can simply regen pub key anyway.
func RSARenGenPubKey(filebasename string, passphrase string) {
	fPrivName := strings.Join([]string{filebasename, "json"}, ".")
	fPubName := strings.Join([]string{filebasename, "pub", "json"}, ".")

	priv := RSAReadEncryptedPrivateKey(fPrivName, passphrase)
	pub := priv.PublicKey
	err := RSAWriteKey(fPubName, pub)
	check(err)
}

func RSAWriteKeyPair(filebasename string, priv *rsa.PrivateKey, pub *rsa.PublicKey, passphrase string) {
	fPrivName := strings.Join([]string{filebasename, "json"}, ".")
	fPubName := strings.Join([]string{filebasename, "pub", "json"}, ".")

	// dump  keys to file
	err := RSAWriteKey(fPubName, pub)
	check(err)
	err = RSAWriteEncryptedPricvateKey(fPrivName, passphrase, priv)
	check(err)

}

func RSAWriteEncryptedPricvateKey(fn string, p string, v interface{}) error {
	ptRSAKey, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("private Key could not be converted to json: %v", err)
	}
	salt := Salt(16)
	key := DeriveKey(KDFTYPE, p, salt)
	ctRSAKey := Encrypt(CHIPERTYPE, key, ptRSAKey)

	return RSAWriteKey(fn, RSAEncryptedPrivateKey{
		Chiper:     CHIPERTYPE,
		KDF:        KDFTYPE,
		Privatekey: ctRSAKey,
		Salt:       salt,
	})

}

func RSAWriteKey(fn string, v interface{}) error {
	f, err := os.Create(fn)
	check(err)
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func RSAReadKeyPair(filebasename string, passphrase string) (sk *rsa.PrivateKey, pk *rsa.PublicKey) {
	fPrivName := strings.Join([]string{filebasename, "json"}, ".")
	fPubName := strings.Join([]string{filebasename, "pub", "json"}, ".")
	// load  keys from file
	pk = RSAReadPublicKey(fPubName)
	sk = RSAReadEncryptedPrivateKey(fPrivName, passphrase)
	return sk, pk
}

func RSAReadEncryptedPrivateKey(fn, p string) *rsa.PrivateKey {
	fkey, err := os.Open(fn)
	check(err)
	defer fkey.Close()
	dec := json.NewDecoder(fkey)
	ctRSAKey := &RSAEncryptedPrivateKey{}
	dec.Decode(ctRSAKey)
	key := DeriveKey(ctRSAKey.KDF, p, ctRSAKey.Salt)
	ptRSAKey := Decrypt(ctRSAKey.Chiper, key, ctRSAKey.Privatekey)

	priv := &rsa.PrivateKey{}
	err = json.Unmarshal(ptRSAKey, priv)
	check(err)
	return priv
}

func RSAReadPrivateKey(fn string) *rsa.PrivateKey {
	fkey, err := os.Open(fn)
	check(err)
	defer fkey.Close()
	dec := json.NewDecoder(fkey)
	key := &rsa.PrivateKey{}
	dec.Decode(key)
	return key
}

func RSAReadPublicKey(fn string) *rsa.PublicKey {
	fkey, err := os.Open(fn)
	check(err)
	defer fkey.Close()
	dec := json.NewDecoder(fkey)
	key := &rsa.PublicKey{}
	dec.Decode(key)
	return key
}
