package auth

import (
	"github.com/pquerna/otp/totp"
	"github.com/tsocial/ts2fa/storage"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

var pritunlUsers = []storage.User{
	{
		Email:     "abc@trustingsocial.com",
		OtpSecret: "7VP7X6OC37YVIRVI",
	},
}
func TestMain(m *testing.M) {
	log.SetFlags(log.LstdFlags)
	storage.PritunlMockServer(pritunlUsers)

	os.Exit(m.Run())
	// run suite
}

func TestValidate(t *testing.T) {
	// Run a mock server and mount Validate middleware in it.
	_ = os.Setenv("TOTP_CONFIG", "testdata/totp_config.json")
	m := mux.NewRouter()
	m.Handle("/test", Validate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respWrite(w, []byte(`{"hello ": "world"}`))
	})))

	testServer := httptest.NewServer(m)

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

	// TODO: add refresh handler tests
	//t.Run("test refresh handler", func(t *testing.T){
	//	m := mux.NewRouter()
	//	m.HandleFunc("/refresh", RefreshHandler)
	//
	//	testServer := httptest.NewServer(m)
	//
	//	req, err := http.NewRequest(http.MethodGet, testServer.URL+"/refresh", nil)
	//	assert.Nil(t, err)
	//
	//	c := http.Client{}
	//
	//	pritunlUsers = append(pritunlUsers, storage.User{"123@trustingsocial.com",
	//		"GMYDQN3GGVRWIY3CMNQWINLFGE3DQOJUHFRDOM3DHBSWEZDGGVRA"})
	//
	//	_, err = c.Do(req)
	//	assert.Nil(t, err)
	//})
}

func respWrite(w http.ResponseWriter, resp []byte) {
	if _, err := w.Write(resp); err != nil {
		log.Printf("response-write-error: %+v", err)
	}
}
