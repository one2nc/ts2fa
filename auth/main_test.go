package auth

import (
	"encoding/json"
	"github.com/pquerna/otp/totp"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
)

var pritunlUsers = []User{
	{
		Email:     "abc@trustingsocial.com",
		OtpSecret: "7VP7X6OC37YVIRVI",
	},
}

func mockPritunlHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	if vars["org_id"] != _pOrgId || r.Header.Get("Auth-Token") != _pToken ||
		r.Header.Get("Auth-Timestamp") == "" || r.Header.Get("Auth-Nonce") == "" ||
		r.Header.Get("Auth-Signature") == "" {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	}

	resp, _ := json.Marshal(&pritunlUsers)

	w.WriteHeader(http.StatusOK)
	respWrite(w, resp)
}

var (
	_pServer *httptest.Server
	_pToken  = uuid.NewV4().String()
	_pSecret = uuid.NewV4().String()
	_pOrgId  = uuid.NewV4().String()
)

func TestMain(m *testing.M) {
	log.SetFlags(log.LstdFlags)

	mx := mux.NewRouter()
	mx.Handle("/user/{org_id}", http.HandlerFunc(mockPritunlHandler))
	_pServer = httptest.NewServer(mx)

	// run mock pritunl server
	// set env values
	_ = os.Setenv("PRITUNL_TOKEN", _pToken)
	_ = os.Setenv("PRITUNL_SECRET", _pSecret)
	_ = os.Setenv("PRITUNL_ORG_ID", _pOrgId)
	_ = os.Setenv("PRITUNL_HOST", _pServer.URL)

	os.Exit(m.Run())
	// run suite
}

func TestValidate(t *testing.T) {
	// Run a mock server and mount Validate middleware in it.
	m := mux.NewRouter()
	m.Handle("/test", Validate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respWrite(w, []byte(`{"hello ": "world"}`))
	})))

	testServer := httptest.NewServer(m)

	t.Run("data should be fetched on the first call", func(t *testing.T) {
		t.Parallel()
		req, err := http.NewRequest(http.MethodGet, testServer.URL+"/test", nil)
		assert.Nil(t, err)

		req.SetBasicAuth("abc@trustingsocial.com", "123123")

		c := http.Client{}

		// store should be nil
		assert.Nil(t, store)

		resp, err := c.Do(req)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.NotNil(t, store)
		assert.Equal(t, 1, len(store.secrets))
	})

	t.Run("should allow request with valid otp", func(t *testing.T) {
		t.Parallel()
		req, err := http.NewRequest(http.MethodGet, testServer.URL+"/test", nil)
		assert.Nil(t, err)

		otp, err := totp.GenerateCode(pritunlUsers[0].OtpSecret, time.Now())
		assert.Nil(t, err)

		req.SetBasicAuth(pritunlUsers[0].Email, otp)

		c := http.Client{}

		resp, err := c.Do(req)
		assert.Nil(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func TestRefreshHandler(t *testing.T) {
	t.Parallel()
	m := mux.NewRouter()
	m.HandleFunc("/refresh", RefreshHandler)

	testServer := httptest.NewServer(m)

	req, err := http.NewRequest(http.MethodGet, testServer.URL+"/refresh", nil)
	assert.Nil(t, err)

	c := http.Client{}

	assert.Equal(t, 1, len(store.secrets))
	pritunlUsers = append(pritunlUsers, User{"abc2@trustingsocial.com", "secret"})

	_, err = c.Do(req)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(store.secrets))
}

func respWrite(w http.ResponseWriter, resp []byte) {
	if _, err := w.Write(resp); err != nil {
		log.Printf("response-write-error: %+v", err)
	}
}
