package hawk

import (
	"testing"
	"time"
)

type stubbedClock struct{}

func (c *stubbedClock) Now(offset time.Duration) int64 {
	return 1365711458
}

func TestBewitConfig_GetBewit(t *testing.T) {
	c := &Credential{
		ID:  "123456",
		Key: "2983d45yun89q",
		Alg: SHA256,
	}

	b1 := NewBewitConfig(c, (24 * time.Hour * 365 * 100))
	b1.Ext = "some-app-data"

	actual1 := b1.GetBewit("http://example.com/resource/4?a=1&b=2", &stubbedClock{})
	expect1 := "MTIzNDU2XDQ1MTkzMTE0NThcYkkwanFlS1prUHE0V1hRMmkxK0NrQ2lOanZEc3BSVkNGajlmbElqMXphWT1cc29tZS1hcHAtZGF0YQ"

	if actual1 != expect1 {
		t.Errorf("invalid bewit: %s", actual1)
	}
}

func TestBewitConfig_GetBewit2(t *testing.T) {
	c := &Credential{
		ID:  "123456",
		Key: "2983d45yun89q",
		Alg: SHA256,
	}

	b1 := NewBewitConfig(c, (24 * time.Hour * 365 * 100))
	b1.Ext = "some-app-data"

	// url parameter is null-string
	actual2 := b1.GetBewit("", &stubbedClock{})
	if actual2 != "" {
		t.Error("expect null-string, but got ", actual2)
	}

	b3 := &BewitConfig{
		Credential: nil,
		Ttl:        24 * time.Hour * 365 * 100,
		Ext:        "some-app-data",
	}

	// credential is nil
	actual3 := b3.GetBewit("http://example.com/resource/4?a=1&b=2", &stubbedClock{})
	if actual3 != "" {
		t.Error("expect null-string, but got ", actual2)
	}

	b4 := &BewitConfig{
		Credential: &Credential{},
		Ttl:        24 * time.Hour * 365 * 100,
		Ext:        "some-app-data",
	}

	// Credential members are nil
	actual4 := b4.GetBewit("http://example.com/resource/4?a=1&b=2", &stubbedClock{})
	if actual4 != "" {
		t.Error("expect null-string, but got ", actual2)
	}

	// Clock is nil
	actual5 := b1.GetBewit("http://example.com/resource/4?a=1&b=2", nil)
	if actual5 == "" {
		t.Error("expect result is not null, but got null value")
	}
}
