package auth

import (
	"fmt"
	"log"
	"net/http"
)


func Validate(f http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lock.RLock()
		var startup bool
		if store == nil {
			startup = true
			lock.RUnlock()
			if err := initStore(); err != nil {
				http.Error(w, fmt.Sprintf("init-store-error: %+v", err), http.StatusInternalServerError)
				return
			}
		}

		if !startup {
			defer lock.RUnlock()
		}

		if email, token, ok := r.BasicAuth(); !ok || !store.isValid(email, token) {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		f.ServeHTTP(w, r)
	})
}

// Fetch data from pritunl and update userStore
func RefreshHandler(w http.ResponseWriter, r *http.Request) {
	data, err := fetchPritunlData()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	store.update(data)

	if _, err := w.Write([]byte(`{"success": true}`)); err != nil {
		log.Printf("response-write-error: %+v", err)
	}
}
