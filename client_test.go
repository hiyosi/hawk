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
	c1 := NewClient(
		&Credential{
			ID:  "test-id",
			Key: "test-key",
			Alg: SHA256,
		},
		&Option{
			TimeStamp: time.Now().Unix(),
			Nonce:     "xyz123",
			Ext:       "sample-ext-string",
		},
	)

	url1 := "https://example.com/test/hawk"
	act1, err := c1.Header("GET", url1)
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
	c2 := NewClient(
		&Credential{
			ID:  "test-id",
			Key: "test-key",
			Alg: SHA256,
		},
		&Option{
			TimeStamp:   time.Now().Unix(),
			Nonce:       "xyz123",
			Ext:         "sample-ext-string",
			ContentType: "text/plain",
			Payload:     "something to write about",
		},
	)

	url2 := "http://example.net/somewhere/over/the/rainbow"
	act2, err := c2.Header("POST", url2)
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
	c3 := NewClient(
		&Credential{
			ID:  "test-id",
			Key: "test-key",
			Alg: SHA256,
		},
		&Option{
			TimeStamp:   time.Now().Unix(),
			Nonce:       "xyz123",
			Ext:         "sample-ext-string",
			ContentType: "text/plain",
			Payload:     "something to write about",
			App:         "some-app-id",
			Dlg:         "some-dlg",
		},
	)

	url3 := "http://example.net/somewhere/over/the/rainbow"
	act3, err := c3.Header("POST", url3)
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
	mockedURL := &url.URL{
		Scheme:   "http",
		Host:     "example.com:8080",
		Path:     "/resource/4",
		RawQuery: "filter=a",
	}

	ts := int64(1453070933)

	// GET
	var mockedHttpServer = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server-Authorization", `Hawk mac="eQVGuMTYgG3ePysLXDnYMSECjvhdGyZX5VPIunNUyJ8=", ext="response-specific"`)
	})
	s := httptest.NewServer(mockedHttpServer)
	defer s.Close()
	r, _ := http.Get(s.URL)
	r.Request.URL = mockedURL

	c := NewClient(
		&Credential{
			ID:  "123456",
			Key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
			Alg: SHA256,
		},
		&Option{
			TimeStamp: ts,
			Nonce:     "3hOHpR",
			Ext:       "some-app-data",
		},
	)

	act, _ := c.Authenticate(r)
	if act != true {
		t.Error("failed to authenticate server response.")
	}

	// POST
	var mockedHttpServer1 = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Server-Authorization", `Hawk mac="odsVGUq0rCoITaiNagW22REIpqkwP9zt5FyqqOW9Zj8=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext="response-specific"`)
		fmt.Fprintf(w, "\n")
	})
	s1 := httptest.NewServer(mockedHttpServer1)
	defer s1.Close()
	r1, _ := http.PostForm(s1.URL, nil)
	r1.Request.URL = mockedURL

	c1 := NewClient(
		&Credential{
			ID:  "123456",
			Key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
			Alg: SHA256,
		},
		&Option{
			TimeStamp:   ts,
			Nonce:       "3hOHpR",
			Ext:         "some-app-data",
			ContentType: "text/plain",
			Payload:     "some reply",
		},
	)

	act1, _ := c1.Authenticate(r1)
	if act1 != true {
		t.Error("failed to authenticate server response.")
	}
}

func TestClient_Authenticate_Fail(t *testing.T) {
	mockedURL := &url.URL{
		Scheme:   "http",
		Host:     "example.com:8080",
		Path:     "/resource/4",
		RawQuery: "filter=a",
	}

	ts := int64(1453070933)

	// calculate mac with different credential.key
	var mockedHttpServer2 = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Server-Authorization", `Hawk mac="odsVGUq0rCoITaiNagW22REIpqkwP9zt5FyqqOW9Zj8=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext="response-specific"`)
		fmt.Fprintf(w, "some reply\n")
	})
	s2 := httptest.NewServer(mockedHttpServer2)
	defer s2.Close()
	r2, _ := http.PostForm(s2.URL, nil)
	r2.Request.URL = mockedURL

	c2 := NewClient(
		&Credential{
			ID:  "123456",
			Key: "some-key",
			Alg: SHA256,
		},
		&Option{
			TimeStamp:   ts,
			Nonce:       "3hOHpR",
			Ext:         "some-app-data",
			ContentType: "text/plain",
			Payload:     "some reply",
		},
	)

	act2, _ := c2.Authenticate(r2)
	if act2 != false {
		t.Error("expected authenticate failed, but actual is successful.")
	}

	// invalid hash value specified
	var mockedHttpServer3 = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Server-Authorization", `Hawk mac="odsVGUq0rCoITaiNagW22REIpqkwP9zt5FyqqOW9Zj8=", hash="f9cDF/TDm7TkYRLnGwRMfeDzT6LixQVLvrIKhh0vgmM=", ext="response-specific"`)
		fmt.Fprintf(w, "some reply\n")
	})
	s3 := httptest.NewServer(mockedHttpServer3)
	defer s3.Close()
	r3, _ := http.PostForm(s3.URL, nil)
	r3.Request.URL = mockedURL

	c3 := NewClient(
		&Credential{
			ID:  "123456",
			Key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
			Alg: SHA256,
		},
		&Option{
			TimeStamp:   ts,
			Nonce:       "3hOHpR",
			Ext:         "some-app-data",
			ContentType: "text/plain",
			Payload:     "invalid some reply",
		},
	)

	act3, _ := c3.Authenticate(r3)
	if act3 != false {
		t.Error("expected authenticate failed, but actual is successful.")
	}
}
