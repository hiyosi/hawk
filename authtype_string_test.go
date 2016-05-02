package hawk

import "testing"

func TestAuthType_String(t *testing.T) {
	t1 := Header
	if t1.String() != "Header" {
		t.Error("unexpected authtype string. expect=Header, actual=" + t1.String())
	}

	t2 := Response
	if t2.String() != "Response" {
		t.Error("unexpected authtype string. expect=Response, actual=" + t2.String())
	}

	t3 := Bewit
	if t3.String() != "Bewit" {
		t.Error("unexpected authtype string. expect=Bewit, actual=" + t3.String())
	}

	var t4 AuthType = 10
	if t4.String() != "AuthType(10)" {
		t.Error("unexpected authtype string. expect=AuthType(10), actual=" + t4.String())
	}
}
