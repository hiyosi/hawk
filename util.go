package hawk

import (
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"strings"
)

func Nonce(n int) (string, error) {
	bytes := make([]byte, n)
	_, err := rand.Read(bytes)
	return hex.EncodeToString(bytes), err
}

func parseHawkHeader(headerVal string) map[string]string {
	attrs := make(map[string]string)

	if headerVal == "" {
		return attrs
	}

	h1 := strings.Split(headerVal, "Hawk ")
	if len(h1) != 2 {
		return attrs
	}
	h2 := strings.Split(h1[1], ", ")

	//FIXME: validate duplication, unknown-key
	for _, v := range h2 {
		r := regexp.MustCompile(`(\w+)="([^"\\]*)"\s*(?:,\s*|$)`)
		group := r.FindSubmatch([]byte(v))
		if len(group) != 3 {
			// ignore. invalid structure
			continue
		}
		attrs[string(group[1])] = string(group[2])
	}

	return attrs
}

// compare strings using fixed time algorithm
func fixedTimeComparison(str1, str2 string) bool {
	var mismatch int32 = 1
	if len(str1) == len(str2) {
		mismatch = 0
	}

	for i, _ := range str1 {
		codeA := []rune(str1)[i]
		codeB := []rune(str2)[i]

		res := (codeA ^ codeB)
		mismatch = mismatch | res
	}

	return mismatch == 0
}
