package hawk

import (
	"testing"
	"unicode/utf8"
)

func Test_Nonce(t *testing.T) {
	byteSize := 10
	act, err := Nonce(byteSize)
	if err != nil {
		t.Error("got an error," + err.Error())
	}

	if utf8.RuneCountInString(act) != byteSize*2 {
		t.Error("expected length=10, but actual length=", utf8.RuneCountInString(act))
	}
}
