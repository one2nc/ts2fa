package ts2fa

import (
	"github.com/tsocial/ts2fa/storage"
	"log"
)

const DEFAULT = "*"

type Rule struct {
	Emails []string `json:"emails"`
	WhitelistedIPs []string `json:"whitelisted_ips"`
}

type Rules map[string]map[string]Rule

type Ts2FAConf struct {
	Rules     Rules    `json:"rules"`
}

type Ts2FA struct {
	rules     Rules
}

type Payload struct {
	Path  string
	Key   string
	SourceIP string
	Email string
	Otp string
}

func NewPayload(p, k, s, e, o string) *Payload {
	return &Payload{p, k, s, e, o}
}

func (t *Ts2FA) Verify(p *Payload) bool {
	if p == nil {
		return true
	}

	log.Println(p)

	action, ok := t.rules[p.Path]
	if !ok {
		action, ok = t.rules[DEFAULT]
	}

	if !ok {
		return true
	}

	rule, ok := action[p.Key]
	if !ok {
		rule, ok = action[DEFAULT]
	}

	if len(rule.WhitelistedIPs) == 0 && len(rule.Emails) == 0 {
		return true
	}

	if p.Email != "" && p.Otp != "" && len(rule.Emails) > 0 {
		log.Println(rule.Emails)
		for _, e := range rule.Emails {
			if e == p.Email {
				return storage.IsValid(p.Email, p.Otp)
			}
		}
	}

	if p.SourceIP != "" {
		for _, w := range rule.WhitelistedIPs {
			if w == p.SourceIP {
				return true
			}
		}
	}

	return false
}

func New(c *Ts2FAConf) *Ts2FA {
	if c == nil {
		c = &Ts2FAConf{}
	}

	if c.Rules == nil {
		c.Rules = Rules{}
	}

	if err := storage.InitStore(); err != nil {
		log.Println(err)
		return nil
	}

	return &Ts2FA{rules: c.Rules}
}
