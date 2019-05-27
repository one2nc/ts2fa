package ts2fa

import (
	"fmt"
	"github.com/tsocial/ts2fa/storage"
	"log"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/pquerna/otp/totp"
)

var pritunlUsers = []storage.User{
		{
			Email:     "abc@trustingsocial.com",
			OtpSecret: "7VP7X6OC37YVIRVI",
		},
		{
			Email:     "123@trustingsocial.com",
			OtpSecret: "GMYDQN3GGVRWIY3CMNQWINLFGE3DQOJUHFRDOM3DHBSWEZDGGVRA",
		},
	}

func TestMain(m *testing.M) {
	log.SetFlags(log.LstdFlags)
	storage.PritunlMockServer(pritunlUsers)
	os.Exit(m.Run())
}

func TestNew(t *testing.T) {
	x := New(nil)
	t.Run("Should have empty rules", func(t *testing.T) {
		assert.NotNil(t, x.rules)
	})
}

func TestVerify(t *testing.T) {
	rules := Rules{
		"/test": map[string]Rule{
			"key1":  {
				Emails: []string{"abc@trustingsocial.com"},
			},
			DEFAULT: {
				Emails: []string{"abc@trustingsocial.com"},
			},
		},
		"/foo": map[string]Rule{
			DEFAULT: {WhitelistedIPs: []string{"1.1.1.1"}},
		},
		DEFAULT: map[string]Rule{
			DEFAULT: {Emails: []string{"123@trustingsocial.com"}},
		},
	}

	log.Println(pritunlUsers)
	x := New(&Ts2FAConf{Rules: rules})
	log.Println(pritunlUsers)
	t.Run("Verify against a nil paylod", func(t *testing.T) {
		assert.True(t, x.Verify(nil), "Validation should pass")
	})

	t.Run("Verify a payload", func(t *testing.T) {
		t.Run("Missing path catches default", func(t *testing.T) {
			p := NewPayload("/missing", "key1", "", "123@trustingsocial.com", "12345")

			t.Run("Invalid default secret", func(t *testing.T) {
				assert.False(t, x.Verify(p), "Should fail validation")
			})

			t.Run("Valid default secret", func(t *testing.T) {
				p.Otp, _ = totp.GenerateCode(pritunlUsers[1].OtpSecret, time.Now())
				assert.True(t, x.Verify(p), fmt.Sprintf("%+v", pritunlUsers[1]))
			})
		})

		t.Run("/test", func(t *testing.T) {
			t.Run("key1", func(t *testing.T) {
				p := NewPayload("/test", "key1", "", "abc@trustingsocial.com", "12345")

				t.Run("Invalid secret", func(t *testing.T) {
					assert.False(t, x.Verify(p), "Should fail validation")
				})

				t.Run("Valid secret", func(t *testing.T) {
					p.Otp, _ = totp.GenerateCode(pritunlUsers[0].OtpSecret, time.Now())
					assert.True(t, x.Verify(p))
				})
			})
		})

	})
}

