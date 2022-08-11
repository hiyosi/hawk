package hawk

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"hash"
	"net"
	"net/url"
	"strconv"
	"strings"
)

const headerVersion = 1

type AuthType int

const (
	Header AuthType = iota
	Response
	Bewit
)

type Mac struct {
	Type       AuthType
	Credential *Credential
	Uri        string
	Method     string
	HostPort   string
	Option     *Option
}

type TsMac struct {
	TimeStamp  int64
	Credential *Credential
}

type PayloadHash struct {
	ContentType string
	Payload     string
	Alg         Alg
}

// String returns a base64 encoded message authentication code.
func (m *Mac) String() (string, error) {
	digest, err := m.digest()
	return base64.StdEncoding.EncodeToString(digest), err
}

func (m *Mac) digest() ([]byte, error) {
	s := getHash(m.Credential.Alg)

	mac := hmac.New(s, []byte(m.Credential.Key))
	ns, err := m.normalized()
	if err != nil {
		return nil, err
	}
	mac.Write([]byte(ns))

	return mac.Sum(nil), nil
}

func (m *Mac) normalized() (string, error) {
	return normalized(m.Type, m.Uri, m.Method, m.HostPort, m.Option)
}

// String returns a base64 encoded message authentication code for timestamp
func (tm *TsMac) String() string {
	digest := tm.digest()
	return base64.StdEncoding.EncodeToString(digest)
}

func (tm *TsMac) digest() []byte {
	s := getHash(tm.Credential.Alg)

	mac := hmac.New(s, []byte(tm.Credential.Key))
	ns := "hawk." + strconv.Itoa(headerVersion) + ".ts" + "\n" + strconv.FormatInt(tm.TimeStamp, 10) + "\n"
	mac.Write([]byte(ns))

	return mac.Sum(nil)
}

// String returns a base64 encoded hash value of payload
func (h *PayloadHash) String() string {
	hash := h.hash()
	return base64.StdEncoding.EncodeToString(hash)
}

func sanitizeContentType(contentType string) string {
	return strings.TrimSpace(strings.ToLower(strings.Split(contentType, ";")[0]))
}

func (h *PayloadHash) hash() []byte {
	s := getHash(h.Alg)()

	ns := "hawk." + strconv.Itoa(headerVersion) + ".payload" + "\n" + sanitizeContentType(h.ContentType) + "\n" + h.Payload + "\n"
	s.Write([]byte(ns))

	return s.Sum(nil)
}

func normalized(authType AuthType, uri, method, customHost string, option *Option) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", err
	}

	var h string
	if customHost != "" {
		h = customHost
	} else {
		h = u.Host
	}

	host, port, _ := net.SplitHostPort(h)
	if port == "" {
		switch u.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}
	if host == "" {
		if customHost != "" {
			host = customHost
		} else {
			host = u.Host
		}
	}

	path := u.Path
	if u.RawPath != "" {
		path = u.RawPath
	}
	if u.Query().Encode() != "" {
		path = path + "?" + u.RawQuery
	}

	header := "hawk" + "." + strconv.Itoa(headerVersion) + "." + strings.ToLower(authType.String())

	ext := ""
	if option.Ext != "" {
		ext = strings.Replace(option.Ext, "\\", "\\\\", -1)
		ext = strings.Replace(ext, "\n", "\\n", -1)
	}

	ns := header + "\n" +
		strconv.FormatInt(option.TimeStamp, 10) + "\n" +
		option.Nonce + "\n" +
		strings.ToUpper(method) + "\n" +
		path + "\n" +
		strings.ToLower(host) + "\n" +
		port + "\n" +
		option.Hash + "\n" +
		ext + "\n"

	if option.App != "" {
		ns = ns + option.App + "\n"
		ns = ns + option.Dlg + "\n"
	}

	return ns, nil
}

func getHash(alg Alg) func() hash.Hash {
	switch alg {
	case SHA256:
		return sha256.New
	case SHA512:
		return sha512.New
	default:
		return sha256.New
	}
}
