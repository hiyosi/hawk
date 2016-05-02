package hawk

import (
	"testing"

	"net/http"
	"time"
)

type testCredentialStore struct {
	ID  string
	Key string
	Alg Alg
}

func (g *testCredentialStore) GetCredential(id string) (*Credential, error) {
	return &Credential{
		ID:  g.ID,
		Key: g.Key,
		Alg: g.Alg,
	}, nil
}

func TestServer_Authenticate(t *testing.T) {
	id := "dh37fgj492je"

	credentialStore := &testCredentialStore{
		ID:  id,
		Key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
		Alg: SHA256,
	}

	c := &Client{
		Credential: &Credential{
			ID:  credentialStore.ID,
			Key: credentialStore.Key,
			Alg: credentialStore.Alg,
		},
		Option: &Option{
			TimeStamp: time.Now().Unix(),
			Nonce:     "3hOHpR",
			Ext:       "some-app-data",
		},
	}

	h, _ := c.Header("GET", "http://example.com:8080/resource/1?b=1&a=2")

	r, _ := http.NewRequest("GET", "http://example.com:8080/resource/1?b=1&a=2", nil)
	r.Header.Set("Authorization", h)

	s := &Server{
		CredentialGetter: credentialStore,
	}

	act, err := s.Authenticate(r)
	if err != nil {
		t.Errorf("return error, %s", err)
	} else {
		expect, _ := credentialStore.GetCredential(id)
		if *act != *expect {
			t.Error("Invalid return value")
		}
	}

	// failed to get credential
	credentialStore1 := &testCredentialStore{}

	s1 := &Server{
		CredentialGetter: credentialStore1,
	}

	act1, err := s1.Authenticate(r)
	if act1 != nil {
		t.Error("got an server autnentication result, expected=nil")
	}

	// specified CustomeHostHeader
	c2 := &Client{
		Credential: &Credential{
			ID:  credentialStore.ID,
			Key: credentialStore.Key,
			Alg: credentialStore.Alg,
		},
		Option: &Option{
			TimeStamp: time.Now().Unix(),
			Nonce:     "3hOHpR",
			Ext:       "some-app-data",
		},
	}

	h2, _ := c2.Header("GET", "http://example.com:8080/resource/1?b=1&a=2")

	r2, _ := http.NewRequest("GET", "http://www.example.com/resource/1?b=1&a=2", nil)
	r2.Header.Set("Authorization", h2)
	r2.Header.Set("X-CUSTOM-HOST", "example.com:8080")

	s2 := &Server{
		CredentialGetter: credentialStore,
		AuthOption: &AuthOption{
			CustomHostNameHeader: "X-CUSTOM-HOST",
		},
	}

	act2, err := s2.Authenticate(r2)
	if err != nil {
		t.Errorf("return error, %s", err)
	} else {
		expect2, _ := credentialStore.GetCredential(id)
		if *act2 != *expect2 {
			t.Error("Invalid return value")
		}
	}

	// specified CustomeHostPort
	c3 := &Client{
		Credential: &Credential{
			ID:  credentialStore.ID,
			Key: credentialStore.Key,
			Alg: credentialStore.Alg,
		},
		Option: &Option{
			TimeStamp: time.Now().Unix(),
			Nonce:     "3hOHpR",
			Ext:       "some-app-data",
		},
	}

	h3, _ := c3.Header("GET", "http://example.com:8080/resource/1?b=1&a=2")

	r3, _ := http.NewRequest("GET", "http://www.example.com/resource/1?b=1&a=2", nil)
	r3.Header.Set("Authorization", h3)
	r3.Header.Set("X-CUSTOM-HOST", "www.example.com:8888")

	s3 := &Server{
		CredentialGetter: credentialStore,
		AuthOption: &AuthOption{
			CustomHostPort: "example.com:8080",
		},
	}

	act3, err := s3.Authenticate(r3)
	if err != nil {
		t.Errorf("return error, %s", err)
	} else {
		expect3, _ := credentialStore.GetCredential(id)
		if *act3 != *expect3 {
			t.Error("Invalid return value")
		}
	}

	// specified payload
	credentialStore4 := &testCredentialStore{
		ID:  id,
		Key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
		Alg: SHA256,
	}

	c4 := &Client{
		Credential: &Credential{
			ID:  credentialStore4.ID,
			Key: credentialStore4.Key,
			Alg: credentialStore4.Alg,
		},
		Option: &Option{
			TimeStamp:   time.Now().Unix(),
			Nonce:       "3hOHpR",
			Ext:         "some-app-data",
			ContentType: "text/plain",
			Payload:     "some reply",
		},
	}

	h4, _ := c4.Header("POST", "http://example.com:8080/resource/1")
	r4, _ := http.NewRequest("POST", "http://example.com:8080/resource/1", nil)
	r4.Header.Set("Authorization", h4)
	r4.Header.Set("Content-Type", "text/plain")

	s4 := &Server{
		CredentialGetter: credentialStore,
		Payload:          "some reply",
	}

	act4, err := s4.Authenticate(r4)
	if err != nil {
		t.Errorf("return error, %s", err)
	} else {
		expect4, _ := credentialStore.GetCredential(id)
		if *act4 != *expect4 {
			t.Error("Invalid return value")
		}
	}

	// NonceValidator return error
	c5 := &Client{
		Credential: &Credential{
			ID:  credentialStore.ID,
			Key: credentialStore.Key,
			Alg: credentialStore.Alg,
		},
		Option: &Option{
			TimeStamp: time.Now().Unix(),
			Nonce:     "3hOHpR",
			Ext:       "some-app-data",
		},
	}

	h5, _ := c5.Header("GET", "http://example.com:8080/resource/1?b=1&a=2")

	r5, _ := http.NewRequest("GET", "http://example.com:8080/resource/1?b=1&a=2", nil)
	r5.Header.Set("Authorization", h5)

	s5 := &Server{
		CredentialGetter: credentialStore,
		NonceValidator:   &errorNonceValidator{},
	}

	_, err = s5.Authenticate(r5)
	if err == nil {
		t.Error("expected return error, buto got nil")
	}

	// stale timestamp
	c6 := &Client{
		Credential: &Credential{
			ID:  credentialStore.ID,
			Key: credentialStore.Key,
			Alg: credentialStore.Alg,
		},
		Option: &Option{
			TimeStamp: int64(1253070933),
			Nonce:     "3hOHpR",
			Ext:       "some-app-data",
		},
	}

	h6, _ := c6.Header("GET", "http://example.com:8080/resource/1?b=1&a=2")

	r6, _ := http.NewRequest("GET", "http://example.com:8080/resource/1?b=1&a=2", nil)
	r6.Header.Set("Authorization", h6)

	s6 := &Server{
		CredentialGetter: credentialStore,
	}

	_, err = s6.Authenticate(r6)
	if err == nil {
		t.Error("expected return error, buto got nil")
	}
}

type errorNonceValidator struct{}

func (n *errorNonceValidator) Validate(key, nonce string, ts int64) bool {
	return false
}

func TestServer_Authenticate_Fail(t *testing.T) {
	id := "dh37fgj492je"

	credentialStore := &testCredentialStore{
		ID:  id,
		Key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
		Alg: SHA256,
	}

	r, _ := http.NewRequest("GET", "http://example.com:8080/resource/1?b=1&a=2", nil)
	r.Header.Set("Authorization", `Hawk id="dh37fgj492je", ts="1234567890", nonce="3hOHpX", ext="some-app-data", mac="NEe0zcKYQtUWtstNnIO4e86RrpH1PdhMPz6X/TK8T5Q="`)

	s := &Server{
		CredentialGetter: credentialStore,
	}

	_, err := s.Authenticate(r)
	if err == nil {
		t.Errorf("Not Returned error.")
	}
}

func TestServer_AuthenticateBewit(t *testing.T) {
	id := "123456"

	credentialStore := &testCredentialStore{
		ID:  id,
		Key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
		Alg: SHA256,
	}

	rawPath := "/resource/4?a=1&b=2&bewit=MTIzNDU2XDQ1MTE0ODQ2MjFcMzFjMmNkbUJFd1NJRVZDOVkva1NFb2c3d3YrdEVNWjZ3RXNmOGNHU2FXQT1cc29tZS1hcHAtZGF0YQ"
	r, _ := http.NewRequest("GET", "http://example.com:8080"+rawPath, nil)
	r.URL.RawPath = rawPath

	s := &Server{
		CredentialGetter: credentialStore,
	}

	act, err := s.AuthenticateBewit(r)
	if err != nil {
		t.Errorf("error, %s", err)
	}

	if act == nil {
		t.Errorf("returned nil.")
	}
}
