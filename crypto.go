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
	AuthHeader AuthType = iota
	AuthResponse
	AuthBewit
)

type Mac struct {
	Type       AuthType
	Credential Credential
	Uri        string
	Method     string
	Option     Option
}

type TsMac struct {
	TimeStamp  int64
	Credential Credential
}

func (m *Mac) String() (string, error) {
	digest, err := m.digest()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(digest), nil
}

func (m *Mac) digest() ([]byte, error) {
	h := getHash(m.Credential.Alg)

	mac := hmac.New(h, []byte(m.Credential.Key))
	ns, err := m.normalized()
	if err != nil {
		return nil, err
	}
	mac.Write([]byte(ns))

	return mac.Sum(nil), nil
}

func (m *Mac) normalized() (string, error) {
	return normalized(m.Type, m.Uri, m.Method, m.Option)
}

func (tm *TsMac) String() string {
	digest := tm.digest()

	return base64.StdEncoding.EncodeToString(digest)
}

func (tm *TsMac) digest() []byte {
	h := getHash(tm.Credential.Alg)

	mac := hmac.New(h, []byte(tm.Credential.Key))
	ns := "hawk." + strconv.Itoa(headerVersion) + ".ts" + "\n" + strconv.FormatInt(tm.TimeStamp, 10) + "\n"
	mac.Write([]byte(ns))

	return mac.Sum(nil)
}

func normalized(authType AuthType, uri string, method string, option Option) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", err
	}

	host := u.Host
	_, port, _ := net.SplitHostPort(u.Host)
	if port == "" {
		switch u.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}
	path := u.Path

	header := "hawk" + "." + strconv.Itoa(headerVersion) + "." + authType.String()

	ns := header + "\n" +
		strconv.FormatInt(option.TimeStamp, 10) + "\n" +
		option.Nonce + "\n" +
		strings.ToUpper(method) + "\n" +
		strings.ToLower(path) + "\n" +
		host + "\n" +
		port + "\n" +
		option.Hash + "\n" +
		option.Ext + "\n"

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
