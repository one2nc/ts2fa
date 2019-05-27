package auth

import (
	"encoding/json"
	"github.com/tsocial/ts2fa/otp"
	"github.com/tsocial/ts2fa/storage"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)


func Validate(f http.Handler) http.Handler {
	configPath := os.Getenv("TOTP_CONFIG")
	if configPath == "" {
		panic("TOTP_CONFIG env is not set")
	}

	configBytes, err := ioutil.ReadFile(configPath)
	if err != nil {
		panic("cannot read TOTP_CONFIG file")
	}

	var c ts2fa.Ts2FAConf

	if err := json.Unmarshal(configBytes, &c); err != nil {
		panic("cannot unmarshal TOTP_CONFIG")
	}

	t := ts2fa.New(&c)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		email, token, _ := r.BasicAuth()
		o := ts2fa.NewPayload(r.URL.Path, r.Method, r.RemoteAddr, email, token)

		if !t.Verify(o) {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		f.ServeHTTP(w, r)
	})
}

// Fetch data from pritunl and update userStore
func RefreshHandler(w http.ResponseWriter, r *http.Request) {
	if err := storage.Refresh(); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}


	if _, err := w.Write([]byte(`{"success": true}`)); err != nil {
		log.Printf("response-write-error: %+v", err)
	}
}
