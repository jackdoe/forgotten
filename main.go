package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh/terminal"
)

type Password struct {
	CreatedTimeStamp uint64
	Value            string
}

type Passwords struct {
	Data map[string]*Password
}

func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func encrypt(data []byte, passphrase string) []byte {
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatal(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

func decrypt(data []byte, passphrase string) []byte {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Fatal(err.Error())
	}
	return plaintext
}

func encryptFile(filename string, data []byte, passphrase string) {
	tmp := fmt.Sprintf("%s.tmp", filename)

	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	_, err = f.Write(encrypt(data, passphrase))
	if err != nil {
		log.Fatal(err)
	}

	err = os.Rename(tmp, filename)
	if err != nil {
		log.Fatal(err)
	}
}

func exists(f string) bool {
	if _, err := os.Stat(f); !os.IsNotExist(err) {
		return true
	}
	return false

}

func decryptFile(filename string, passphrase string) []byte {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}

	return decrypt(data, passphrase)
}

func getHome() string {
	home := os.Getenv("HOME")
	if home == "" {
		usr, err := user.Current()
		if err != nil {
			log.Fatal(err)
		}
		home = usr.HomeDir
	}
	return home
}

func main() {
	home := getHome()

	var pkey = flag.String("key", "generic", "get password for key (e.g gmail/jack)")
	var pfile = flag.String("file", path.Join(home, ".forgotten.aes"), "file to read/write")
	var ppass = flag.String("passphrase", "-", "passphrase input (- for stdin)")

	flag.Parse()
	var masterPassword string
	if *ppass == "-" {
		fmt.Fprint(os.Stderr, "Enter Master Password: ")
		bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Fatal(err)
		} else {
			masterPassword = string(bytePassword)
		}
		fmt.Fprint(os.Stderr, "\n")
	} else {
		b, err := ioutil.ReadFile(*ppass)
		if err != nil {
			log.Fatal(err)
		}
		masterPassword = string(b)
	}

	passwords := &Passwords{
		Data: map[string]*Password{},
	}
	if exists(*pfile) {
		bpasswords := decryptFile(*pfile, masterPassword)
		err := json.Unmarshal(bpasswords, passwords)
		if err != nil {
			log.Fatal(err)
		}
	}
	p, ok := passwords.Data[*pkey]
	if ok {
		fmt.Printf("%s\n", p.Value)
		os.Exit(0)
	}

	ran, err := Generate(32, 2, 2, false, false)
	if err != nil {
		log.Fatal(err)
	}
	passwords.Data[*pkey] = &Password{
		Value:            ran,
		CreatedTimeStamp: uint64(time.Now().UnixNano()),
	}

	bpasswords, err := json.Marshal(passwords)
	if err != nil {
		log.Fatal(err)
	}
	encryptFile(*pfile, bpasswords, masterPassword)
	fmt.Printf("%s\n", ran)
	os.Exit(0)
}
