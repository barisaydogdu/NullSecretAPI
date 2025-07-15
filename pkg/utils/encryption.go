package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"os"
)

func GetAESEncrypted(plainText string) (string, error) {
	key := []byte(os.Getenv("AES_KEY"))
	iv := []byte(os.Getenv("AES_IV"))

	var plaintextBlock []byte
	plenght := len(plainText)

	if plenght%16 != 0 {
		extendBlock := 16 - (plenght % 16)
		plaintextBlock = make([]byte, plenght+extendBlock)
		copy(plaintextBlock[plenght:], bytes.Repeat([]byte{uint8(extendBlock)}, extendBlock))
	} else {
		plaintextBlock = make([]byte, plenght)
	}

	copy(plaintextBlock, plainText)
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	cipherText := make([]byte, len(plaintextBlock))

	mode := cipher.NewCBCEncrypter(block, []byte(iv))
	mode.CryptBlocks(cipherText, plaintextBlock)

	str := base64.StdEncoding.EncodeToString(cipherText)

	return str, nil

}

func GetAESDecrypt(encrypted string) ([]byte, error) {
	//Todo:iv will be random not static
	key := []byte(os.Getenv("AES_KEY"))
	iv := []byte(os.Getenv("AES_IV"))

	cipherText, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	if len(cipherText)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("block size cant be zero")
	}

	mode := cipher.NewCBCDecrypter(block, []byte(iv))
	mode.CryptBlocks(cipherText, cipherText)
	//remove the padding
	cipherText = PKCS7Padding(cipherText)

	return cipherText, nil
}

func PKCS7Padding(src []byte) []byte {
	lenght := len(src)
	unPadding := int(src[lenght-1])

	return src[:lenght-unPadding]

}
