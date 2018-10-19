package main

import (
	"bufio"
	"crypto/md5"
	"encoding/base32"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/mdp/qrterminal"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

var (
	email   = flag.String("email", "", "Email to generate QR Code for")
	project = flag.String("project", "SRE", "Project to generate QR Code for")
)

const (
	Issuer    = "TrustingSocial"
	Period    = 120 //Period for which Totp is valid for
	Algorithm = "SHA1"
	Digits    = "6" //Digits to use in OTP
)

func displayQR(b string) {
	qrterminal.GenerateHalfBlock(b, qrterminal.L, os.Stdout)
}

func promptForPasscode() string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter OTP: ")
	text, _ := reader.ReadString('\n')
	return text
}

func makeSecret(args ...string) string {
	h := md5.New()
	for _, v := range args {
		io.WriteString(h, v)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func makeUrl(issuer, email, project string) *url.URL {
	// otpauth://totp/Ex:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example
	v := url.Values{}
	secret := makeSecret(email, project)
	v.Set("secret", strings.TrimRight(base32.StdEncoding.EncodeToString([]byte(secret)), "="))
	v.Set("issuer", Issuer)
	v.Set("period", strconv.FormatUint(uint64(Period), 10))
	v.Set("algorithm", Algorithm)
	v.Set("digits", Digits)

	return &url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/" + Issuer + ":" + email,
		RawQuery: v.Encode(),
	}
}

func main() {
	flag.Parse()
	if len(*email) == 0 {
		log.Println("Must provide an email address")
		os.Exit(127)
	}

	key, err := otp.NewKeyFromURL(makeUrl(Issuer, *email, *project).String())
	if err != nil {
		panic(err)
	}

	// display the QR code to the user.
	displayQR(key.String())

	for {
		// Now Validate that the user's successfully added the passcode.
		passcode := promptForPasscode()
		valid := totp.Validate(passcode, key.Secret())
		if valid {
			log.Println("Secret:", key.Secret())
			os.Exit(0)
		}
	}
}
