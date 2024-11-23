// main.go
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type EncryptRequest struct {
	Algorithm string `json:"algorithm"`
	Message   string `json:"message"`
}

type DecryptRequest struct {
	Algorithm       string `json:"algorithm"`
	EncryptedMessage string `json:"encryptedMessage"`
}

type EncryptResponse struct {
	EncryptedMessage string `json:"encryptedMessage"`
}

type DecryptResponse struct {
	DecryptedMessage string `json:"decryptedMessage"`
}

type SignRequest struct {
	Algorithm string `json:"algorithm"`
	Message   string `json:"message"`
}

type SignResponse struct {
	Signature string `json:"signature"`
}

type VerifyRequest struct {
	Algorithm string `json:"algorithm"`
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

type VerifyResponse struct {
	IsValid bool `json:"isValid"`
}

func encryptHandler(w http.ResponseWriter, r *http.Request) {
	var req EncryptRequest
	json.NewDecoder(r.Body).Decode(&req)

	switch strings.ToUpper(req.Algorithm) {
	case "RSA":
		encryptedMessage, err := encryptLongMessage(req.Message) 
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	
		json.NewEncoder(w).Encode(EncryptResponse{EncryptedMessage: encryptedMessage})
	

	case "ELGAMAL":
		encryptedMessage, err := encryptElGamal(req.Message)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(EncryptResponse{EncryptedMessage: encryptedMessage})
	case "ECC":
		encryptedMessage, err := encryptECC(req.Message)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(EncryptResponse{EncryptedMessage: encryptedMessage})
	}
	
}

func decryptHandler(w http.ResponseWriter, r *http.Request) {
	var req DecryptRequest
	json.NewDecoder(r.Body).Decode(&req)

	switch strings.ToUpper(req.Algorithm) {
	case "RSA":
		decryptedMessage, err := decryptLongMessage(req.EncryptedMessage)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(DecryptResponse{DecryptedMessage: decryptedMessage})

	case "ELGAMAL":
		decryptedMessage, err := decryptElGamal(req.EncryptedMessage)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(DecryptResponse{DecryptedMessage: decryptedMessage})
	case "ECC":
		decryptedMessage, err := decryptECC(req.EncryptedMessage)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(DecryptResponse{DecryptedMessage: decryptedMessage})
	}
	
}

// Hàm xử lý tạo chữ ký số (signHandler)
func signHandler(w http.ResponseWriter, r *http.Request) {
	var req SignRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	var signature string
	switch strings.ToUpper(req.Algorithm) {
	case "RSA":
		// Tạo chữ ký số bằng RSA
		signature, err = signMessage(req.Message)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case "ELGAMAL":
		// Tạo chữ ký số bằng Elgamal
		signature, err = signElGamal(req.Message)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case "ECC":
		// Tạo chữ ký số bằng ECC
		signature, err = signECC(req.Message)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	default:
		http.Error(w, "Unsupported algorithm", http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(SignResponse{Signature: signature})
}

// Hàm xử lý xác thực chữ ký số (verifyHandler)
func verifyHandler(w http.ResponseWriter, r *http.Request) {
	var req VerifyRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	var isValid bool
	switch strings.ToUpper(req.Algorithm) {
	case "RSA":
		// Xác thực chữ ký số bằng RSA
		isValid = verifySignature(req.Message, req.Signature)
	case "ELGAMAL":
		// Xác thực chữ ký số bằng Elgamal
		isValid,_ = verifyElGamal(req.Message, req.Signature)
	case "ECC":
		// Xác thực chữ ký số bằng ECC
		isValid,_ = verifyECC(req.Message, req.Signature)
	default:
		http.Error(w, "Unsupported algorithm", http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(VerifyResponse{IsValid: isValid})
}


// Middleware xử lý CORS
func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Access-Control-Allow-Origin", "*") // Cho phép tất cả các nguồn
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
        w.Header().Set("Access-Control-Allow-Credentials", "true")

        // Đáp ứng yêu cầu preflight của CORS
        if r.Method == http.MethodOptions {
            w.WriteHeader(http.StatusOK)
            return
        }

        next.ServeHTTP(w, r)
    }
}

func main() {
	generateRSAKeys(2048)
	generateElGamalKeys(512)
	generateECCKeys()
	generateECCKey()

	http.HandleFunc("/encrypt", corsMiddleware(encryptHandler))
    http.HandleFunc("/decrypt", corsMiddleware(decryptHandler))

	http.HandleFunc("/sign", corsMiddleware(signHandler)) 
	http.HandleFunc("/verify", corsMiddleware(verifyHandler)) 

	fmt.Println("Server is running on http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}
