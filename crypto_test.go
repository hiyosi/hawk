package hawk

import (
	"testing"

	"time"
)

func TestMac_String(t *testing.T) {
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

func TestPayloadHash_Hash(t *testing.T) {
	h := &PayloadHash{
		ContentType: "text/plain",
		Payload: "Thank you for flying Hawk",
		Alg: SHA256,
	}

	expect := "Yi9LfIIFRtBEPt74PVmbTF/xVAwPn7ub15ePICfgnuY="
	actual := h.String()

	if actual != expect {
		t.Error("invalid payload hash string.")
	}
}