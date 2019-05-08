package hawk

import (
	"testing"
)

func TestMac_String(t *testing.T) {
	m := &Mac{
		Type: Header,
		Credential: &Credential{
			ID:  "dh37fgj492je",
			Key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
			Alg: SHA256,
		},
		Uri:    "http://example.com:8000/resource/1?b=1&a=2",
		Method: "GET",
		Option: &Option{
			TimeStamp: int64(1353832234),
			Nonce:     "j4h3g2",
			Ext:       "some-app-ext-data",
		},
	}

	act, err := m.String()
	if err != nil {
		t.Error("got an error", err.Error())
	}

	// expected value is reference from https://github.com/hueniverse/hawk#protocol-example
	expect := "6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE="

	if act != expect {
		t.Error("invalid mac.")
	}
}

func TestMac_String_With_CustomHost(t *testing.T) {
	m1 := &Mac{
		Type: Header,
		Credential: &Credential{
			ID:  "dh37fgj492je",
			Key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
			Alg: SHA256,
		},
		Uri:      "http://www.example.com/resource/1?b=1&a=2",
		HostPort: "example.com:8000",
		Method:   "GET",
		Option: &Option{
			TimeStamp: int64(1353832234),
			Nonce:     "j4h3g2",
			Ext:       "some-app-ext-data",
		},
	}

	act1, err := m1.String()
	if err != nil {
		t.Error("got an error", err.Error())
	}
	expect1 := "6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE="

	if act1 != expect1 {
		t.Error("invalid mac.")
	}

	// specified HostPort String.
	m2 := &Mac{
		Type: Header,
		Credential: &Credential{
			ID:  "dh37fgj492je",
			Key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
			Alg: SHA256,
		},
		Uri:      "http://www.example.com/resource/1?b=1&a=2",
		HostPort: "example.com",
		Method:   "GET",
		Option: &Option{
			TimeStamp: int64(1353832234),
			Nonce:     "j4h3g2",
			Ext:       "some-app-ext-data",
		},
	}

	act2, err := m2.String()
	if err != nil {
		t.Error("got an error", err.Error())
	}
	expect2 := "fmzTiKheFFqAeWWoVIt6vIflByB9X8TeYQjCdvq9bf4="

	if act2 != expect2 {
		t.Error("invalid mac.")
	}

	// specified App and Dlg
	m3 := &Mac{
		Type: Header,
		Credential: &Credential{
			ID:  "dh37fgj492je",
			Key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
			Alg: SHA256,
		},
		Uri:    "http://example.com:8080/resource/1?b=1&a=2",
		Method: "GET",
		Option: &Option{
			TimeStamp: int64(1353832234),
			Nonce:     "j4h3g2",
			Ext:       "some-app-ext-data",
			App:       "some-app-id",
			Dlg:       "some-dlg",
		},
	}

	act3, err := m3.String()
	if err != nil {
		t.Error("got an error", err.Error())
	}
	expect3 := "3glACULyTDnGSBEBpkFbRxRTFSXauan/Jk7NpA1MKl0="

	if act3 != expect3 {
		t.Error("invalid mac.")
	}
}

func TestTsMac_String(t *testing.T) {
	tm := &TsMac{
		TimeStamp: 1365741469,
		Credential: &Credential{
			ID:  "123456",
			Key: "2983d45yun89q",
			Alg: SHA256,
		},
	}

	act := tm.String()
	expect := "h/Ff6XI1euObD78ZNflapvLKXGuaw1RiLI4Q6Q5sAbM="

	if act != expect {
		t.Error("Invalid TsMac result")
	}
}

func TestPayloadHash_String(t *testing.T) {
	h := &PayloadHash{
		ContentType: "text/plain",
		Payload:     "Thank you for flying Hawk",
		Alg:         SHA256,
	}

	// expected value is reference from https://github.com/hueniverse/hawk#payload-validation
	expect := "Yi9LfIIFRtBEPt74PVmbTF/xVAwPn7ub15ePICfgnuY="
	actual := h.String()

	if actual != expect {
		t.Error("invalid payload hash string.")
	}

	h2 := &PayloadHash{
		ContentType: "text/plain; charset=utf-8",
		Payload:     "Thank you for flying Hawk",
		Alg:         SHA256,
	}

	// expected value shouldn't change from ContentType changing
	actual2 := h2.String()

	if actual2 != expect {
		t.Error("invalid payload hash string when given ContentType with parameters.")
	}
}
