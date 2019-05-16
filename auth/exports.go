package auth

import (
	"log"
	"net/http"
	"sync"
)

var lock sync.Mutex

func Validate(f http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if store == nil {
			initStore()
		}

		if email, token, ok := r.BasicAuth(); !ok || !store.IsValid(email, token) {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		}

		f.ServeHTTP(w, r)
	})
}

// Fetch data from pritunl and update userStore
func RefreshHandler(w http.ResponseWriter, r *http.Request) {
	data, err := fetchPritunlData()
	if err != nil {
		panic(err)
	}
	store.Update(data)

	if _, err := w.Write([]byte(`{"success": true}`)); err != nil {
		log.Printf("response-write-error: %+v", err)
	}
}

func initStore() {
	lock.Lock()
	defer lock.Unlock()

	if store != nil {
		return
	}

	store = &secretStore{
		Secrets: make(map[string]string),
	}

	data, err := fetchPritunlData()
	if err != nil {
		panic(err)
	}
	store.Update(data)
}
