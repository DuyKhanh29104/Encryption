package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math"
	"strings"
)

var rsaPrivateKey *rsa.PrivateKey
var rsaPublicKey *rsa.PublicKey

// Tạo cặp khóa RSA
func generateRSAKeys(bits int) {
	var err error
	rsaPrivateKey, err = rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		fmt.Println("Error generating RSA keys:", err)
		return
	}
	rsaPublicKey = &rsaPrivateKey.PublicKey
}

// Mã hóa RSA
func encryptRSA(message string) (string, error) {
	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		rsaPublicKey,
		[]byte(message),
		nil,
	)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encryptedBytes), nil
}

// Giải mã RSA
func decryptRSA(encryptedMessage string) (string, error) {
	ciphertext, _ := base64.StdEncoding.DecodeString(encryptedMessage)
	decryptedBytes, err := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		rsaPrivateKey,
		ciphertext,
		nil,
	)
	if err != nil {
		return "", err
	}
	return string(decryptedBytes), nil
}

// Chia nhỏ thông điệp và mã hóa từng khối, sau đó nối các khối lại thành một chuỗi duy nhất
func encryptLongMessage(message string) (string, error) {
	// Xác định kích thước khối dựa trên khóa RSA
	blockSize := rsaPublicKey.Size() - 2*sha256.Size - 2
	var encryptedMessage string

	// Chia nhỏ thông điệp thành các khối và mã hóa từng khối, nối lại thành một chuỗi
	for start := 0; start < len(message); start += blockSize {
		end := int(math.Min(float64(start+blockSize), float64(len(message))))
		encryptedBlock, err := encryptRSA(message[start:end])
		if err != nil {
			return "", err
		}
		// Nối các khối lại thành một chuỗi
		encryptedMessage += encryptedBlock + ","
	}

	// Xóa dấu phẩy cuối cùng
	if len(encryptedMessage) > 0 {
		encryptedMessage = encryptedMessage[:len(encryptedMessage)-1]
	}

	return encryptedMessage, nil
}

// Giải mã từng khối và ghép lại thông điệp ban đầu
func decryptLongMessage(encryptedMessage string) (string, error) {
	var decryptedMessage string

	// Chia thông điệp thành các khối
	encryptedBlocks := strings.Split(encryptedMessage, ",")

	// Giải mã từng khối và ghép lại thành thông điệp ban đầu
	for _, encryptedBlock := range encryptedBlocks {
		decryptedBlock, err := decryptRSA(encryptedBlock)
		if err != nil {
			return "", err
		}
		decryptedMessage += decryptedBlock
	}

	return decryptedMessage, nil
}

// Tạo chữ ký số (Digital Signature)
func signMessage(message string) (string, error) {
	// Hash thông điệp bằng SHA-256
	hashed := sha256.Sum256([]byte(message))
	// Ký thông điệp đã được hash
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, 0, hashed[:])
	if err != nil {
		return "", err
	}
	// Mã hóa chữ ký bằng Base64
	return base64.StdEncoding.EncodeToString(signature), nil
}

// Xác thực chữ ký số (Verify Digital Signature)
func verifySignature(message string, signature string) bool {
	// Hash thông điệp bằng SHA-256
	hashed := sha256.Sum256([]byte(message))
	// Giải mã chữ ký từ Base64
	signatureBytes, _ := base64.StdEncoding.DecodeString(signature)
	// Xác thực chữ ký bằng khóa công khai
	err := rsa.VerifyPKCS1v15(rsaPublicKey, 0, hashed[:], signatureBytes)
	return err == nil
}

