package hwcipher_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"math/rand"
	"testing"

	"github.com/gyf304/go-crypto-cipher-hw/hwcipher"
)

type setIV interface {
	SetIV([]byte)
}

func TestBasic(t *testing.T) {
	keyLen := 32
	key := make([]byte, keyLen)
	iv := []byte("0123456789012345")

	block, _ := aes.NewCipher(key)
	mode := cipher.NewCBCEncrypter(block, iv)
	// make 4KiB of plaintext
	plaintext := make([]byte, 4096)
	swCiphertext := make([]byte, len(plaintext))

	for i := 0; i < 1000; i++ {
		mode.CryptBlocks(swCiphertext, plaintext)
	}

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
	for i := 0; i < 1000; i++ {
		hwMode.CryptBlocks(hwCiphertext, plaintext)
	}

	if !bytes.Equal(swCiphertext, hwCiphertext) {
		t.Error("Software and hardware encryption results are not equal")
	}
}

func TestRandom(t *testing.T) {
	for i := 0; i < 100; i++ {
		keyLen := 16 * (rand.Intn(2) + 1)
		key := make([]byte, keyLen)
		iv := make([]byte, 16)
		rand.Read(key)
		rand.Read(iv)

		swBlock, _ := aes.NewCipher(key)
		decrypt := rand.Intn(2) == 0
		var swMode cipher.BlockMode
		if decrypt {
			swMode = cipher.NewCBCDecrypter(swBlock, iv)
		} else {
			swMode = cipher.NewCBCEncrypter(swBlock, iv)
		}
		hwMode, err := hwcipher.NewAfAlg(&hwcipher.AfAlgConfig{
			AlgType: "skcipher",
			AlgName: "cbc(aes)",
			Key:     key,
			IV:      iv,
			Decrypt: decrypt,
		})
		if err != nil {
			t.Error(err)
		}
		for j := 0; j < 100; j++ {
			plaintextLen := (rand.Intn(64) + 1) * 16
			plaintext := make([]byte, plaintextLen)
			swCiphertext := make([]byte, plaintextLen)
			hwCiphertext := make([]byte, plaintextLen)
			rand.Read(plaintext)
			swMode.CryptBlocks(swCiphertext, plaintext)
			hwMode.CryptBlocks(hwCiphertext, plaintext)
			if !bytes.Equal(swCiphertext, hwCiphertext) {
				t.Errorf("Software and hardware encryption results are not equal, keyLen=%d, i=%d, j=%d", keyLen, i, j)
				return
			}
			newIV := make([]byte, 16)
			rand.Read(newIV)
			swMode.(setIV).SetIV(newIV)
			hwMode.SetIV(newIV)
		}
	}
}
