package hawk

import (
	"testing"

	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"
)

func TestClient_Header(t *testing.T) {
	c := &Client{
		Credential: &Credential{
			ID:  "test-id",
			Key: "test-key",
			Alg: SHA256,
		},
		Option: &Option{
			TimeStamp: time.Now().Unix(),
			Nonce:     "xyz123",
			Ext:       "sample-ext-string",
		},
	}

	url := "https://example.com/test/hawk"
	act, err := c.Header(url, "GET")
	if err != nil {
		t.Error("got an error,", err.Error())
	}

	if !strings.Contains(act, "Hawk") {
		t.Error("actual not contains 'Authorization: Hawk'")
	}
	if !strings.Contains(act, "id=") {
		t.Error("actual not contains 'id' attribute")
	}
	if !strings.Contains(act, "ts=") {
		t.Error("actual not contains 'ts' attribute")
	}
	if !strings.Contains(act, "nonce=") {
		t.Error("actual not contains 'nonce' attribute")
	}
	if !strings.Contains(act, "ext=") {
		t.Error("actual not contains 'ext=' attribute")
	}
}

func TestClient_Authenticate(t *testing.T) {
	var mockedHttpServer = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Server-Authorization", `Hawk mac="odsVGUq0rCoITaiNagW22REIpqkwP9zt5FyqqOW9Zj8=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext="response-specific"`)
		fmt.Fprintf(w, "some reply\n")
	})

	s := httptest.NewServer(mockedHttpServer)
	defer s.Close()

	r, err := http.PostForm(s.URL, nil)
	if err != nil {
		fmt.Println(err)
		return
	}

	mockedURL := &url.URL{
		Scheme:   "http",
		Host:     "example.com:8080",
		Path:     "/resource/4",
		RawQuery: "filter=a",
	}
	r.Request.URL = mockedURL

	ts := int64(1453070933)
	c := &Client{
		Credential: &Credential{
			ID:  "123456",
			Key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
			Alg: SHA256,
		},
		Option: &Option{
			TimeStamp:   ts,
			Nonce:       "3hOHpR",
			Ext:         "some-app-data",
			ContentType: "text/plain",
			Payload:     "some reply",
			Hash:        "nJjkVtBE5Y/Bk38Aiokwn0jiJxt/0S2WRSUwWLCf5xk=",
		},
	}

	act, _ := c.Authenticate(r)

	if act != true {
		t.Error("failed to authenticate server response.")
	}
}
