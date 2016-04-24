package hawk

import (
	"testing"

	"strings"
	"time"
)

func TestClient_Header(t *testing.T) {
	c := &Client{
		Credential: &Credential{
			ID: "test-id",
			Key: "test-key",
			Alg: SHA256,
		},
		Option: &Option{
			TimeStamp: time.Now().Unix(),
			Nonce: "xyz123",
			Ext: "sample-ext-string",
		},
	}

	url := "https://example.com/test/hawk"
	act, err := c.Header(url, "GET")
	if err != nil {
		t.Error("got an error,", err)
	}

	if !strings.Contains(act, "Authorization: Hawk") {
		t.Error("actual not contains 'Authorization: Hawk'")
	}
	if !strings.Contains(act, "id") {
		t.Error("actual not contains 'id' attribute")
	}
	if !strings.Contains(act, "ts") {
		t.Error("actual not contains 'ts' attribute")
	}
	if !strings.Contains(act, "nonce") {
		t.Error("actual not contains 'nonce' attribute")
	}
	if !strings.Contains(act, "ext") {
		t.Error("actual not contains 'ext' attribute")
	}
}