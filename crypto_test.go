package hawk

import (
	"testing"

	"time"
)

func TestString(t *testing.T) {
	ts := time.Now().Unix()
	nonce := "xyz123"
	m := &Mac{
		Type: AuthHeader,
		Credential: &Credential{
			ID: "test-id",
			Key: "test-key",
			Alg: SHA256,
		},
		Uri: "https://example.com/test/hawk",
		Method: "GET",
		Option: &Option{
			TimeStamp: ts,
			Nonce: nonce,
			Ext: "test-ext-data",
		},
	}

	act, err := m.String()
	if err != nil {
		t.Error("got an error", err.Error())
	}

	if act == "" {
		t.Errorf("expected not '' but got %s", act)
	}

}