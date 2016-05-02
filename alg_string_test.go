package hawk

import "testing"

func TestAlg_String(t *testing.T) {
	a1 := SHA256
	if a1.String() != "SHA256" {
		t.Error("unexpected authtype string. expect=SHA256, actual=" + a1.String())
	}

	a2 := SHA512
	if a2.String() != "SHA512" {
		t.Error("unexpected authtype string. expect=SHA256, actual=" + a2.String())
	}

	var a3 Alg = 10
	if a3.String() != "Alg(10)" {
		t.Error("unexpected authtype string. expect=Alg(10), actual=" + a3.String())
	}
}
