// This is a Programm to test some crypto stuff will reading and watching crypto-textbook.com

package main

import (
	"flag"
	"fmt"
	"sync"
)

const (
	// Defaults
	DEFAULTMSG          = "super secret message"
	DEFAULTPASSHRASE    = "MySecretPasspharse"
	DEFAULTFILEBASENAME = "Keys/rsa"
)

func main() {
	// cmdline arguments
	genkey := flag.Bool("g", false, "Generates Keys")
	regenpubkey := flag.Bool("r", false, "Regenpuv")
	keysize := flag.Int("b", 4096, "Key Bit Size")
	filebasename := flag.String("f", DEFAULTFILEBASENAME, "Basename of Keyfiles")
	passphrase := flag.String("p", DEFAULTPASSHRASE, "Passphrase")
	message := flag.String("m", DEFAULTMSG, "PlainText")
	signmessage := flag.Bool("s", false, "Sign Message")
	encryptmessage := flag.Bool("e", false, "Encrypt and Decrypted Message")
	derivekeys := flag.Bool("d", false, "Derive Keys")
	flag.Parse()
	var wg sync.WaitGroup
	transport := make(chan []byte)

	fmt.Printf(">>>>>>>> START <<<<<<<<<<\n------------\n")
	if *genkey {
		genKey(*filebasename, *keysize, *passphrase)
	}

	if *regenpubkey {
		reGenPubkey(*filebasename, *passphrase)
	}

	if *encryptmessage {
		// Just to show how channels work. I start decryption before actually encryiption. :-)
		go decryptMessage(&wg, *filebasename, *passphrase, transport)
		wg.Add(1)
		go encryptMessage(&wg, *filebasename, *message, *passphrase, transport)
		wg.Add(1)
	}

	if *signmessage {
		go signMessage(&wg, *filebasename, *message, *passphrase, transport)
		wg.Add(1)
		go verifyMessage(&wg, *filebasename, transport)
		wg.Add(1)
	}

	if *derivekeys {
		deriveKeys(*passphrase)
	}
	wg.Wait()
	fmt.Println(">>>>>>>> END <<<<<<<<<<")
}
