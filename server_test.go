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

	// NonceValidator return error
	c1 := &Client{
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

	h1, _ := c1.Header("GET", "http://example.com:8080/resource/1?b=1&a=2")

	r1, _ := http.NewRequest("GET", "http://example.com:8080/resource/1?b=1&a=2", nil)
	r1.Header.Set("Authorization", h1)

	s1 := &Server{
		CredentialGetter: credentialStore,
		NonceValidator:   &errorNonceValidator{},
	}

	_, err = s1.Authenticate(r1)
	if err == nil {
		t.Error("expected return error, buto got nil")
	}

	// stale timestamp
	c2 := &Client{
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

	h2, _ := c2.Header("GET", "http://example.com:8080/resource/1?b=1&a=2")

	r2, _ := http.NewRequest("GET", "http://example.com:8080/resource/1?b=1&a=2", nil)
	r2.Header.Set("Authorization", h2)

	s2 := &Server{
		CredentialGetter: credentialStore,
	}

	_, err = s2.Authenticate(r2)
	if err == nil {
		t.Error("expected return error, buto got nil")
	}

	// Authorization Header is null
	r3, _ := http.NewRequest("GET", "http://example.com:8080/resource/1?b=1&a=2", nil)

	s3 := &Server{
		CredentialGetter: credentialStore,
	}

	_, err = s3.Authenticate(r3)
	if err == nil {
		t.Error("expected return error, buto got nil")
	}

	// failed to get credential
	credentialStore1 := &testCredentialStore{}

	s4 := &Server{
		CredentialGetter: credentialStore1,
	}

	act4, err := s4.Authenticate(r3)
	if act4 != nil {
		t.Error("got an server autnentication result, expected=nil")
	}

	// invalid header value. case-1
	r5, _ := http.NewRequest("GET", "http://example.com:8080/resource/1?b=1&a=2", nil)
	r5.Header.Set("Authorization", "Hawk invalid-header")

	s5 := &Server{
		CredentialGetter: credentialStore,
	}

	act5, err := s5.Authenticate(r5)
	if act5 != nil {
		t.Error("got an server autnentication result, expected=nil")
	}

	// invalid header value. case-2
	r6, _ := http.NewRequest("GET", "http://example.com:8080/resource/1?b=1&a=2", nil)
	r6.Header.Set("Authorization", "invalid-header")

	s6 := &Server{
		CredentialGetter: credentialStore,
	}

	act6, err := s6.Authenticate(r6)
	if act6 != nil {
		t.Error("got an server autnentication result, expected=nil")
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

	// custome HostHeader specified
	rawPath1 := "/resource/4?a=1&b=2&bewit=MTIzNDU2XDQ1MTE0ODQ2MjFcMzFjMmNkbUJFd1NJRVZDOVkva1NFb2c3d3YrdEVNWjZ3RXNmOGNHU2FXQT1cc29tZS1hcHAtZGF0YQ"
	r1, _ := http.NewRequest("GET", "http://www.example.com"+rawPath1, nil)
	r1.URL.RawPath = rawPath1
	r1.Header.Set("X-CUSTOM-HOST", "example.com:8080")

	s1 := &Server{
		CredentialGetter: credentialStore,
		AuthOption: &AuthOption{
			CustomHostNameHeader: "X-CUSTOM-HOST",
		},
	}
	act1, err := s1.AuthenticateBewit(r1)
	if err != nil {
		t.Errorf("error, %s", err)
	}
	if act1 == nil {
		t.Errorf("returned nil.")
	}

	// custom HostPort specified
	rawPath2 := "/resource/4?a=1&b=2&bewit=MTIzNDU2XDQ1MTE0ODQ2MjFcMzFjMmNkbUJFd1NJRVZDOVkva1NFb2c3d3YrdEVNWjZ3RXNmOGNHU2FXQT1cc29tZS1hcHAtZGF0YQ"
	r2, _ := http.NewRequest("GET", "http://www.example.com"+rawPath2, nil)
	r2.URL.RawPath = rawPath2

	s2 := &Server{
		CredentialGetter: credentialStore,
		AuthOption: &AuthOption{
			CustomHostPort: "example.com:8080",
		},
	}
	act2, err := s2.AuthenticateBewit(r2)
	if err != nil {
		t.Errorf("error, %s", err)
	}
	if act2 == nil {
		t.Errorf("returned nil.")
	}
}

func TestServer_AuthenticateBewit_Fail(t *testing.T) {
	id := "123456"

	credentialStore := &testCredentialStore{
		ID:  id,
		Key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
		Alg: SHA256,
	}

	// no bewit param specified
	rawPath1 := "/resource/4?a=1&b="
	r1, _ := http.NewRequest("GET", "http://example.com:8080"+rawPath1, nil)
	r1.URL.RawPath = rawPath1

	s1 := &Server{
		CredentialGetter: credentialStore,
	}
	act1, err := s1.AuthenticateBewit(r1)
	if err == nil {
		t.Error("expected got an error, but actual is nil")
	}
	if act1 != nil {
		t.Errorf("expected nil but, returned not nil.")
	}

	// invalid method
	rawPath2 := "/resource/4?a=1&b=2&bewit=MTIzNDU2XDQ1MTE0ODQ2MjFcMzFjMmNkbUJFd1NJRVZDOVkva1NFb2c3d3YrdEVNWjZ3RXNmOGNHU2FXQT1cc29tZS1hcHAtZGF0YQ"
	r2, _ := http.NewRequest("POST", "http://example.com:8080"+rawPath2, nil)
	r2.URL.RawPath = rawPath2

	s2 := &Server{
		CredentialGetter: credentialStore,
	}
	act2, err := s2.AuthenticateBewit(r2)
	if err == nil {
		t.Error("expected got an error, but actual is nil")
	}
	if act2 != nil {
		t.Errorf("expected nil but, returned not nil.")
	}

	// Authorization Header specified
	rawPath3 := "/resource/4?a=1&b=2&bewit=MTIzNDU2XDQ1MTE0ODQ2MjFcMzFjMmNkbUJFd1NJRVZDOVkva1NFb2c3d3YrdEVNWjZ3RXNmOGNHU2FXQT1cc29tZS1hcHAtZGF0YQ"
	r3, _ := http.NewRequest("GET", "http://example.com:8080"+rawPath3, nil)
	r3.URL.RawPath = rawPath3
	r3.Header.Set("Authorization", "some-authorization-header-value")

	s3 := &Server{
		CredentialGetter: credentialStore,
	}
	act3, err := s3.AuthenticateBewit(r3)
	if err == nil {
		t.Error("expected got an error, but actual is nil")
	}
	if act3 != nil {
		t.Errorf("expected nil but, returned not nil.")
	}

	// no url-safe encoded param
	rawPath4 := "/resource/4?a=1&b=2&bewit=aW52YWxpZC1iZXdpdC1zdHJpbmc="
	r4, _ := http.NewRequest("GET", "http://example.com:8080"+rawPath4, nil)
	r4.URL.RawPath = rawPath4

	s4 := &Server{
		CredentialGetter: credentialStore,
	}
	act4, err := s4.AuthenticateBewit(r4)
	if err == nil {
		t.Error("expected got an error, but actual is nil")
	}
	if act4 != nil {
		t.Errorf("expected nil but, returned not nil.")
	}

	// invalid bewit param
	rawPath5 := "/resource/4?a=1&b=2&bewit=aW52YWxpZC1iZXdpdC1zdHJpbmc"
	r5, _ := http.NewRequest("GET", "http://example.com:8080"+rawPath5, nil)
	r5.URL.RawPath = rawPath5

	s5 := &Server{
		CredentialGetter: credentialStore,
	}
	act5, err := s5.AuthenticateBewit(r5)
	if err == nil {
		t.Error("expected got an error, but actual is nil")
	}
	if act5 != nil {
		t.Errorf("expected nil but, returned not nil.")
	}

	// missing bewit value
	rawPath6 := "/resource/4?a=1&b=2&bewit=XFxc"
	r6, _ := http.NewRequest("GET", "http://example.com:8080"+rawPath6, nil)
	r6.URL.RawPath = rawPath6

	s6 := &Server{
		CredentialGetter: credentialStore,
	}
	act6, err := s6.AuthenticateBewit(r6)
	if err == nil {
		t.Error("expected got an error, but actual is nil")
	}
	if act6 != nil {
		t.Errorf("expected nil but, returned not nil.")
	}

	// invalid timestamp
	rawPath7 := "/resource/4?a=1&b=2&bewit=MTIzNDU2XDEzNjU3MTE0NThcRnpKUmllbWFaNGI2WHU4eVAxeHdMcGZPdE0rd2gyMitHUnVCbEpmaFdQbz1cc29tZS1hcHAtZGF0YQ"
	r7, _ := http.NewRequest("GET", "http://example.com:8080"+rawPath7, nil)
	r7.URL.RawPath = rawPath7

	s7 := &Server{
		CredentialGetter: credentialStore,
	}
	act7, err := s7.AuthenticateBewit(r7)
	if err == nil {
		t.Error("expected got an error, but actual is nil")
	}
	if act7 != nil {
		t.Errorf("expected nil but, returned not nil.")
	}

	// failed to get credential
	credentialStore8 := &testCredentialStore{
		ID: id,
	}

	rawPath8 := "/resource/4?a=1&b=2&bewit=MTIzNDU2XDQ1MTE0ODQ2MjFcMzFjMmNkbUJFd1NJRVZDOVkva1NFb2c3d3YrdEVNWjZ3RXNmOGNHU2FXQT1cc29tZS1hcHAtZGF0YQ"
	r8, _ := http.NewRequest("GET", "http://example.com:8080"+rawPath8, nil)
	r8.URL.RawPath = rawPath8

	s8 := &Server{
		CredentialGetter: credentialStore8,
	}
	act8, err := s8.AuthenticateBewit(r8)
	if err == nil {
		t.Error("expected got an error, but actual is nil")
	}
	if act8 != nil {
		t.Errorf("expected nil but, returned not nil.")
	}

	// invalid mac
	rawPath9 := "/resource/4?a=1&b=2&bewit=MTIzNDU2XDQ1MTE0ODQ2MjFcMzFjMmNkbUJFd1NJRVZDOVkva1NFb2c3d3YrdEVNWjZ3RXNmOGNHU2FXQT1cc29tZS1hcHAtZGF0YQ"
	r9, _ := http.NewRequest("GET", "http://www.example.com"+rawPath9, nil)
	r9.URL.RawPath = rawPath9

	s9 := &Server{
		CredentialGetter: credentialStore,
	}
	act9, err := s9.AuthenticateBewit(r9)
	if err == nil {
		t.Error("expected got an error, but actual is nil")
	}
	if act9 != nil {
		t.Errorf("expected nil but, returned not nil.")
	}
}

func TestServer_Header(t *testing.T) {
	credentialStore := &testCredentialStore{
		ID:  "123456",
		Key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
		Alg: SHA256,
	}

	cred := &Credential{
		ID:  credentialStore.ID,
		Key: credentialStore.Key,
		Alg: credentialStore.Alg,
	}

	option := &Option{
		TimeStamp:   int64(1398546787),
		Payload:     "some reply",
		ContentType: "text/plain",
		Ext:         "response-specific",
	}

	s := &Server{
		CredentialGetter: credentialStore,
	}

	r, _ := http.NewRequest("POST", "http://example.com:8080/resource/4?filter=a", nil)
	r.Header.Set("Authorization", `Hawk mac="dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=", ts="1398546787", nonce="xUwusx", ext="some-app-data", hash="nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk="`)
	r.Header.Set("Content-Type", "text/plain")

	act, err := s.Header(r, cred, option)
	expect := `Hawk mac="n14wVJK4cOxAytPUMc5bPezQzuJGl5n7MYXhFQgEKsE=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext="response-specific"`

	if err != nil {
		t.Error("unexpected error, ", err)
	}
	if act != expect {
		t.Error("unexpected header response, actual=" + act)
	}

	// CustomHostHeader specified
	r1, _ := http.NewRequest("POST", "http://www.example.com/resource/4?filter=a", nil)
	r1.Header.Set("Authorization", `Hawk mac="dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=", ts="1398546787", nonce="xUwusx", ext="some-app-data", hash="nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk="`)
	r1.Header.Set("Content-Type", "text/plain")
	r1.Header.Set("X-CUSTOM-HOST", "example.com:8080")

	s1 := &Server{
		CredentialGetter: credentialStore,
		AuthOption: &AuthOption{
			CustomHostNameHeader: "X-CUSTOM-HOST",
		},
	}

	act1, err := s1.Header(r1, cred, option)
	expect1 := `Hawk mac="n14wVJK4cOxAytPUMc5bPezQzuJGl5n7MYXhFQgEKsE=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext="response-specific"`

	if err != nil {
		t.Error("unexpected error, ", err)
	}
	if act1 != expect1 {
		t.Error("unexpected header response, actual=" + act1)
	}

	// CustomeHostPort specified
	r2, _ := http.NewRequest("POST", "http://www.example.com/resource/4?filter=a", nil)
	r2.Header.Set("Authorization", `Hawk mac="dvIvMThwi28J61Jc3P0ryAhuKpanU63GXdx6hkmQkJA=", ts="1398546787", nonce="xUwusx", ext="some-app-data", hash="nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk="`)
	r2.Header.Set("Content-Type", "text/plain")

	s2 := &Server{
		CredentialGetter: credentialStore,
		AuthOption: &AuthOption{
			CustomHostPort: "example.com:8080",
		},
	}

	act2, err := s2.Header(r2, cred, option)
	expect2 := `Hawk mac="n14wVJK4cOxAytPUMc5bPezQzuJGl5n7MYXhFQgEKsE=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext="response-specific"`

	if err != nil {
		t.Error("unexpected error, ", err)
	}
	if act2 != expect2 {
		t.Error("unexpected header response, actual=" + act2)
	}
}
