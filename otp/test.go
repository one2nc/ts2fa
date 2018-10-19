package ts2fa

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
)

func sixDigits() int64 {
	max := big.NewInt(999999)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		log.Fatal(err)
	}
	return n.Int64()
}

const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func randString(n int) string {
	bytes := make([]byte, n)
	_, err := rand.Read(bytes)
	if err != nil {
		fmt.Println("error:", err)
		return ""
	}

	for i, b := range bytes {
		bytes[i] = letters[b%byte(len(letters))]
	}

	return string(bytes)
}

func TestValidator(fn Validate) (string, string, Validate) {
	pre_token := fmt.Sprintf("%v", sixDigits())
	pre_secret := randString(20)
	return pre_secret, pre_token, func(k, v string) bool {
		if k == pre_token && v == pre_secret {
			return true
		}

		return fn(k, v)
	}
}
