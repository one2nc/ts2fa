package ts2fa

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pquerna/otp/totp"
)

func TestMain(m *testing.M) {
	m.Run()
}

func TestNew(t *testing.T) {
	x := New(nil)
	t.Run("Should have default validator", func(t *testing.T) {
		assert.NotNil(t, x.validator)
	})

	t.Run("Should have empty rules", func(t *testing.T) {
		assert.NotNil(t, x.rules)
	})
}

func TestVerify(t *testing.T) {
	secret, token, v := TestValidator(totp.Validate)

	rules := Rules{
		"/test": map[string][]string{
			"key1":  []string{secret},
			DEFAULT: []string{"secret1", "secret2"},
		},
		"/foo": map[string][]string{
			DEFAULT: []string{},
		},
		DEFAULT: map[string][]string{
			DEFAULT: []string{secret},
		},
	}

	x := New(&Ts2FAConf{Rules: rules, Validator: v})

	t.Run("Verify against a nil paylod", func(t *testing.T) {
		ok, err := x.Verify(nil)
		t.Run("Err should not ne nil", func(t *testing.T) {
			assert.Nil(t, err, "Error should be nil")
		})

		t.Run("Ok should be true", func(t *testing.T) {
			assert.True(t, ok, "Validation should pass")
		})
	})

	t.Run("Verify a payload", func(t *testing.T) {
		t.Run("Missing path catches default", func(t *testing.T) {
			p := NewPayload("/missing", "key1", "12345")

			t.Run("Invalid default secret", func(t *testing.T) {
				ok, err := x.Verify(p)
				assert.False(t, ok, "Should fail validation")
				assert.Contains(t, err.Error(), fmt.Sprintf("validation failed for Secret: %v", secret))
			})

			t.Run("Valid default secret", func(t *testing.T) {
				p.Codes = []string{token}
				ok, err := x.Verify(p)
				assert.True(t, ok)
				assert.Nil(t, err)
			})
		})

		t.Run("/test", func(t *testing.T) {
			t.Run("key1", func(t *testing.T) {
				p := NewPayload("/test", "key1", "12345")

				t.Run("Invalid secret", func(t *testing.T) {
					ok, err := x.Verify(p)
					assert.False(t, ok, "Should fail validation")
					assert.Contains(t, err.Error(), fmt.Sprintf("validation failed for Secret: %v", secret))
				})

				t.Run("Valid secret", func(t *testing.T) {
					p.Codes = []string{token}
					ok, err := x.Verify(p)
					assert.True(t, ok)
					assert.Nil(t, err)
				})
			})

			t.Run("Default key", func(t *testing.T) {
				p := NewPayload("/test", "key2", "12345")

				t.Run("Insufficient tokens", func(t *testing.T) {
					ok, err := x.Verify(p)
					assert.False(t, ok, "Should fail validation")
					assert.Contains(t, err.Error(), "Expected 2 got 1")
				})

				t.Run("Sufficient but incorrect codes", func(t *testing.T) {
					p.Codes = []string{"12", "34"}
					ok, err := x.Verify(p)
					assert.False(t, ok, "Should fail validation")
					assert.Contains(t, err.Error(), "validation failed for Secret:")
				})
			})
		})

		t.Run("/foo", func(t *testing.T) {
			t.Run("Any key", func(t *testing.T) {
				p := NewPayload("/foo", "key2", "12345")

				t.Run("No token needed", func(t *testing.T) {
					ok, err := x.Verify(p)
					assert.True(t, ok)
					assert.Nil(t, err)
				})
			})
		})
	})
}
