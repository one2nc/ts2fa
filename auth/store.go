package auth

import (
	"log"
	"sync"

	"github.com/pquerna/otp/totp"
)

type User struct {
	Email     string `json:"email"`
	OtpSecret string `json:"otp_secret"`
}

type secretStore struct {
	sync.RWMutex
	Secrets map[string]string
}

var store *secretStore

func (s *secretStore) Update(users []User) {
	s.Lock()
	defer s.Unlock()

	if s.Secrets == nil {
		s.Secrets = make(map[string]string)
	}

	for _, u := range users {
		if u.Email != "" && u.OtpSecret != "" {
			s.Secrets[u.Email] = u.OtpSecret
		}
	}
}

func (s *secretStore) IsValid(e, t string) bool {
	if e == "" || t == "" {
		return false
	}

	s.RLock()
	defer s.RUnlock()

	secret, ok := s.Secrets[e]
	if !ok {
		log.Println("otp-validation-error: secret not found")
		return false
	}

	return totp.Validate(t, secret)
}
