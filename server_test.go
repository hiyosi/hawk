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

	h, _ := c.Header("http://example.com:8080/resource/1?b=1&a=2", "GET")

	r, _ := http.NewRequest("GET", "http://example.com:8080/resource/1?b=1&a=2", nil)
	r.Header.Set("Authorization", h)

	s := &Server{
		CredentialGetter: credentialStore,
	}

	act, err := s.Authenticate(r, nil)
	if err != nil {
		t.Errorf("return error, %s", err)
	} else {
		expect, _ := credentialStore.GetCredential(id)
		if *act != *expect {
			t.Error("Invalid return value")
		}
	}
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

	_, err := s.Authenticate(r, nil)
	if err == nil {
		t.Errorf("Not Returned error.")
	}
}