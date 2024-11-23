// ecc.go
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
)

// Định nghĩa các tham số của đường cong elliptic
var curveA = big.NewInt(2)
var curveB = big.NewInt(3)
var curveP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 521), big.NewInt(1)) // P = 2^521 - 1

var eccPrivateKey *big.Int
var eccPublicKeyX, eccPublicKeyY *big.Int

// Hàm tính modulo nghịch đảo
func modInverse(k, p *big.Int) *big.Int {
	return new(big.Int).ModInverse(k, p)
}

// Hàm tìm một điểm hợp lệ trên đường cong elliptic
func findOnePointOnCurve() (*big.Int, *big.Int, error) {
	for x := big.NewInt(0); x.Cmp(curveP) < 0; x.Add(x, big.NewInt(1)) {
		rhs := new(big.Int).Mod(new(big.Int).Add(
			new(big.Int).Add(new(big.Int).Exp(x, big.NewInt(3), curveP),
				new(big.Int).Mul(curveA, x)),
			curveB), curveP)

		y := new(big.Int).ModSqrt(rhs, curveP)
		if y != nil {
			return x, y, nil
		}
	}
	return nil, nil, errors.New("No valid point found on curve")
}

// Hàm sinh khóa ECC
func generateECCKeys() {
	eccPrivateKey, _ = rand.Int(rand.Reader, curveP)
	eccPublicKeyX, eccPublicKeyY, _ = findOnePointOnCurve()
	fmt.Println("ECC Private Key:", eccPrivateKey)
	fmt.Println("ECC Public Key:", eccPublicKeyX, eccPublicKeyY)
}

// Hàm nhân điểm trên đường cong elliptic
func pointMultiply(k *big.Int, x, y *big.Int) (*big.Int, *big.Int) {
	rx, ry := big.NewInt(0), big.NewInt(0)
	tempX, tempY := x, y

	for k.Cmp(big.NewInt(0)) > 0 {
		if new(big.Int).And(k, big.NewInt(1)).Cmp(big.NewInt(1)) == 0 {
			rx, ry = pointAdd(rx, ry, tempX, tempY)
		}
		tempX, tempY = pointAdd(tempX, tempY, tempX, tempY)
		k.Rsh(k, 1)
	}

	return rx, ry
}

// Hàm cộng hai điểm trên đường cong elliptic
func pointAdd(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	if x1.Cmp(big.NewInt(0)) == 0 && y1.Cmp(big.NewInt(0)) == 0 {
		return x2, y2
	}
	if x2.Cmp(big.NewInt(0)) == 0 && y2.Cmp(big.NewInt(0)) == 0 {
		return x1, y1
	}

	var m *big.Int
	if x1.Cmp(x2) == 0 && y1.Cmp(y2) == 0 {
		num := new(big.Int).Add(new(big.Int).Mul(big.NewInt(3), new(big.Int).Mul(x1, x1)), curveA)
		den := new(big.Int).Mul(big.NewInt(2), y1)
		m = new(big.Int).Mod(new(big.Int).Mul(num, modInverse(den, curveP)), curveP)
	} else {
		num := new(big.Int).Sub(y2, y1)
		den := new(big.Int).Sub(x2, x1)
		m = new(big.Int).Mod(new(big.Int).Mul(num, modInverse(den, curveP)), curveP)
	}

	rx := new(big.Int).Mod(new(big.Int).Sub(new(big.Int).Mul(m, m), new(big.Int).Add(x1, x2)), curveP)
	ry := new(big.Int).Mod(new(big.Int).Sub(new(big.Int).Mul(m, new(big.Int).Sub(x1, rx)), y1), curveP)

	return rx, ry
}

// Hàm mã hóa ECC với việc chia nhỏ thông điệp thành các khối
func encryptECC(message string) (string, error) {
    // Kích thước khối
    blockSize := 60
    var encryptedMessage string

    // Chia thông điệp thành các khối
    for start := 0; start < len(message); start += blockSize {
        end := int(math.Min(float64(start+blockSize), float64(len(message))))
        block := message[start:end]

        msgInt := new(big.Int).SetBytes([]byte(block))
        if msgInt.Cmp(curveP) >= 0 {
            return "", errors.New("Message block is too large")
        }

        // Tạo số ngẫu nhiên k
        k, _ := rand.Int(rand.Reader, curveP)

        // Tính toán điểm C1 và C2
        C1x, C1y := pointMultiply(k, eccPublicKeyX, eccPublicKeyY)
        Px, Py := pointMultiply(k, eccPublicKeyX, eccPublicKeyY)
        C2x, C2y := pointAdd(msgInt, big.NewInt(0), Px, Py)

        // Kết hợp C1, C2 thành một chuỗi
        encryptedMessage += fmt.Sprintf("%s|%s|%s|%s|", C1x.String(), C1y.String(), C2x.String(), C2y.String())
    }

    // Loại bỏ dấu '|' cuối cùng
    encryptedMessage = encryptedMessage[:len(encryptedMessage)-1]

    return encryptedMessage, nil
}


// Hàm giải mã ECC với việc xử lý từng khối
func decryptECC(encryptedMessage string) (string, error) {
    parts := strings.Split(encryptedMessage, "|")
    if len(parts)%4 != 0 {
        return "", errors.New("Invalid encrypted message format")
    }

    var decryptedMessage string

    // Giải mã từng khối
    for i := 0; i < len(parts); i += 4 {
        C1x, _ := new(big.Int).SetString(parts[i], 10)
        C1y, _ := new(big.Int).SetString(parts[i+1], 10)
        C2x, _ := new(big.Int).SetString(parts[i+2], 10)
        C2y, _ := new(big.Int).SetString(parts[i+3], 10)

        // Tính toán điểm tempX và tempY bằng việc nhân điểm C1 với khóa riêng
        tempX, tempY := pointMultiply(eccPrivateKey, C1x, C1y)
        tempY.Neg(tempY).Mod(tempY, curveP)

        // Tính toán Mx bằng cách cộng C2 với điểm temp
        Mx, _ := pointAdd(C2x, C2y, tempX, tempY)

        // Chuyển đổi Mx thành chuỗi và thêm vào thông điệp đã giải mã
        decryptedMessage += string(Mx.Bytes())
    }

    return decryptedMessage, nil
}


// Định nghĩa tham số đường cong elliptic (P-521 curve)
var curve = elliptic.P521()

// Khai báo khóa ECC
var privateKey *ecdsa.PrivateKey
var publicKey *ecdsa.PublicKey

// Hàm sinh khóa ECC
func generateECCKey() error {
	var err error
	privateKey, err = ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return err
	}
	publicKey = &privateKey.PublicKey
	fmt.Println("ECC Private Key:", privateKey.D)
	fmt.Println("ECC Public Key:", publicKey.X, publicKey.Y)
	return nil
}

// Hàm ký thông điệp sử dụng ECC
func signECC(message string) (string, error) {
	// Băm thông điệp
	hash := sha256.New()
	hash.Write([]byte(message))
	hashedMessage := hash.Sum(nil)

	// Ký thông điệp với khóa riêng
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashedMessage)
	if err != nil {
		return "", err
	}

	// Trả về chữ ký dưới dạng chuỗi
	signature := fmt.Sprintf("%s|%s", r.Text(16), s.Text(16))
	return signature, nil
}

// Hàm xác minh chữ ký ECC
func verifyECC(message, signature string) (bool, error) {
	// Băm thông điệp
	hash := sha256.New()
	hash.Write([]byte(message))
	hashedMessage := hash.Sum(nil)

	// Phân tách chữ ký thành r và s
	parts := strings.Split(signature, "|")
	if len(parts) != 2 {
		return false, errors.New("invalid signature format")
	}

	r := new(big.Int)
	r, ok := r.SetString(parts[0], 16)
	if !ok {
		return false, errors.New("invalid r value in signature")
	}

	s := new(big.Int)
	s, ok = s.SetString(parts[1], 16)
	if !ok {
		return false, errors.New("invalid s value in signature")
	}

	// Xác minh chữ ký với khóa công khai
	valid := ecdsa.Verify(publicKey, hashedMessage, r, s)
	return valid, nil
}
