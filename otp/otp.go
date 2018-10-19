package ts2fa

import (
	"fmt"

	"github.com/pquerna/otp/totp"
)

const DEFAULT = "*"

type Rules map[string]map[string][]string
type Validate func(token, secret string) bool

type Ts2FAConf struct {
	Rules     Rules `json:"rule"`
	Validator Validate
}

type Ts2FA struct {
	rules     Rules
	validator Validate
}

type Payload struct {
	Path  string
	Key   string
	Codes []string
}

func NewPayload(path, key string, codes ...string) *Payload {
	return &Payload{Path: path, Key: key, Codes: codes}
}

func (t *Ts2FA) SetRules(r Rules) {
	t.rules = r
}

func (t *Ts2FA) SetValidator(v Validate) {
	t.validator = v
}

func (t *Ts2FA) Verify(p *Payload) (bool, error) {
	rule, ok := t.rules[p.Path]
	if !ok {
		return true, nil
	}

	validators, ok := rule[p.Key]
	if !ok {
		validators, ok = rule[DEFAULT]
	}

	if !ok || len(validators) == 0 {
		return true, nil
	}

	if len(validators) != len(p.Codes) {
		return false, fmt.Errorf(
			"invalid no. of Tokens passed. Expected %v got %v",
			len(validators), len(p.Codes))
	}

	for ix, v := range validators {
		if !t.validator(p.Codes[ix], v) {
			return false, fmt.Errorf("validation failed for Secret: %v\n", v)
		}
	}

	return true, nil
}

func New(c *Ts2FAConf) *Ts2FA {
	v := c.Validator
	if v == nil {
		v = totp.Validate
	}

	return &Ts2FA{rules: c.Rules, validator: v}
}
