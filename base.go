package hawk

import (
	"regexp"
	"strings"
)

type Credential struct {
	ID  string
	Key string
	Alg Alg
}

type Option struct {
	TimeStamp   int64
	Nonce       string
	Payload     string
	ContentType string
	Hash        string
	Ext         string
	App         string
	Dlg         string
}

type Alg int

const (
	_ Alg = iota
	SHA256
	SHA512
)

func parseHawkHeader(headerVal string) map[string]string {
	attrs := make(map[string]string)

	hv := strings.Split(strings.Split(headerVal, "Hawk ")[1], ", ")

	for _, v := range hv {
		r := regexp.MustCompile(`(\w+)="([^"\\]*)"\s*(?:,\s*|$)`)
		group := r.FindSubmatch([]byte(v))
		attrs[string(group[1])] = string(group[2])
	}

	return attrs
}
