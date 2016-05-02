package hawk

import "testing"

func TestAlg_String(t *testing.T) {
	a1 := SHA256
	if a1.String() != "SHA256" {
		t.Error("unexpected authtype string. expect=SHA256, actual=" + a1.String())
	}

	a2 := SHA256
	if a2.String() != "SHA512" {
		t.Error("unexpected authtype string. expect=SHA256, actual=" + a2.String())
	}
}
