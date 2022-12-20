package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/gyf304/go-crypto-cipher-hw/hwcipher"
)

func printResult(name string, dur time.Duration) {
	fmt.Println(name, "took", dur, "BW", float64(4096*1024)/dur.Seconds()/1024/1024, "MiB/s")
}

func main() {
	// 256 bits
	keyLen := 32
	if len(os.Args) > 1 {
		keyLen, _ = strconv.Atoi(os.Args[1])
	}
	key := make([]byte, keyLen)
	iv := []byte("0123456789012345")

	block, _ := aes.NewCipher(key)
	mode := cipher.NewCBCEncrypter(block, iv)
	// make 4KiB of plaintext
	plaintext := make([]byte, 4096)
	swCiphertext := make([]byte, len(plaintext))

	swStart := time.Now()
	for i := 0; i < 1000; i++ {
		mode.CryptBlocks(swCiphertext, plaintext)
	}
	swEnd := time.Now()
	swDuration := swEnd.Sub(swStart)
	printResult("Software", swDuration)

	hwMode, err := hwcipher.NewAfAlg(&hwcipher.AfAlgConfig{
		AlgType: "skcipher",
		AlgName: "cbc(aes)",
		Key:     key,
		IV:      iv,
		Decrypt: false,
	})
	if err != nil {
		panic(err)
	}

	hwCiphertext := make([]byte, len(plaintext))
	hwStart := time.Now()
	for i := 0; i < 1000; i++ {
		hwMode.CryptBlocks(hwCiphertext, plaintext)
	}
	hwEnd := time.Now()
	hwDuration := hwEnd.Sub(hwStart)
	printResult("Hardware", hwDuration)
	if string(swCiphertext) != string(hwCiphertext) {
		panic("ciphertexts don't match")
	}
}
