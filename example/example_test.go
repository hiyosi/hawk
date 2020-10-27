package hawk_test

import (
	"fmt"
	"github.com/hiyosi/hawk"
	"time"
)

func ExampleClient_Header() {
	now := time.Date(2016, 5, 01, 9, 00, 00, 0, time.UTC)

	c := &hawk.Client{
		Credential: &hawk.Credential{
			ID:  "123456",
			Key: "test-key",
			Alg: hawk.SHA256,
		},
		Option: &hawk.Option{
			TimeStamp: now.Unix(),
			Nonce:     "xyz123",
			Ext:       "some-ext-string",
		},
	}

	h, err := c.Header("GET", "http://example.com/test/hawk")
	if err != nil {
		fmt.Println("failed to get header.")
	}
	fmt.Println(h)

	// Output:
	// Hawk id="123456", ts="1462093200", nonce="xyz123", ext="some-ext-string", mac="nYSAgaU+v2eFRnY7z0x7/fAFlGmCNXqFo8Cl91q8sbI="
}
