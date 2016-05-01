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
	c1 := &Client{
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

	url1 := "https://example.com/test/hawk"
	act1, err := c1.Header(url1, "GET")
	if err != nil {
		t.Error("got an error,", err.Error())
	}

	if !strings.Contains(act1, "Hawk") {
		t.Error("actual not contains 'Authorization: Hawk'")
	}
	if !strings.Contains(act1, "id=") {
		t.Error("actual not contains 'id' attribute")
	}
	if !strings.Contains(act1, "ts=") {
		t.Error("actual not contains 'ts' attribute")
	}
	if !strings.Contains(act1, "nonce=") {
		t.Error("actual not contains 'nonce' attribute")
	}
	if !strings.Contains(act1, "ext=") {
		t.Error("actual not contains 'ext=' attribute")
	}

	// specified payload
	c2 := &Client{
		Credential: &Credential{
			ID:  "test-id",
			Key: "test-key",
			Alg: SHA256,
		},
		Option: &Option{
			TimeStamp:   time.Now().Unix(),
			Nonce:       "xyz123",
			Ext:         "sample-ext-string",
			ContentType: "text/plain",
			Payload:     "something to write about",
		},
	}

	url2 := "http://example.net/somewhere/over/the/rainbow"
	act2, err := c2.Header(url2, "POST")
	if err != nil {
		t.Error("got an error,", err.Error())
	}

	if !strings.Contains(act2, "Hawk") {
		t.Error("actual not contains 'Authorization: Hawk'")
	}
	if !strings.Contains(act2, "id=") {
		t.Error("actual not contains 'id' attribute")
	}
	if !strings.Contains(act2, "ts=") {
		t.Error("actual not contains 'ts' attribute")
	}
	if !strings.Contains(act2, "nonce=") {
		t.Error("actual not contains 'nonce' attribute")
	}
	if !strings.Contains(act2, "ext=") {
		t.Error("actual not contains 'ext=' attribute")
	}
	if !strings.Contains(act2, "hash=") {
		t.Error("actual not contains 'hash=' attribute")
	}

	// specified app and dlg param
	c3 := &Client{
		Credential: &Credential{
			ID:  "test-id",
			Key: "test-key",
			Alg: SHA256,
		},
		Option: &Option{
			TimeStamp:   time.Now().Unix(),
			Nonce:       "xyz123",
			Ext:         "sample-ext-string",
			ContentType: "text/plain",
			Payload:     "something to write about",
			App:         "some-app-id",
			Dlg:         "some-dlg",
		},
	}

	url3 := "http://example.net/somewhere/over/the/rainbow"
	act3, err := c3.Header(url3, "POST")
	if err != nil {
		t.Error("got an error,", err.Error())
	}

	if !strings.Contains(act3, "Hawk") {
		t.Error("actual not contains 'Authorization: Hawk'")
	}
	if !strings.Contains(act3, "id=") {
		t.Error("actual not contains 'id' attribute")
	}
	if !strings.Contains(act3, "ts=") {
		t.Error("actual not contains 'ts' attribute")
	}
	if !strings.Contains(act3, "nonce=") {
		t.Error("actual not contains 'nonce' attribute")
	}
	if !strings.Contains(act3, "ext=") {
		t.Error("actual not contains 'ext=' attribute")
	}
	if !strings.Contains(act3, "hash=") {
		t.Error("actual not contains 'hash=' attribute")
	}
	if !strings.Contains(act3, "app=") {
		t.Error("actual not contains 'app=' attribute")
	}
	if !strings.Contains(act3, "dlg=") {
		t.Error("actual not contains 'dlg=' attribute")
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
