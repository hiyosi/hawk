package hawk

import (
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"net/http"
	"strings"
	"errors"
	"regexp"
)

type Client struct {
	Credential *Credential
	Option     *Option
}

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

func (c *Client) Header(uri string, method string) (string, error) {
	m := &Mac{
		Type: Header,
		Credential: c.Credential,
		Uri: uri,
		Method: method,
		Option: c.Option,
	}

	mac, err := m.String()
	if err != nil {
		return "", err
	}

	header := "Authorization: Hawk " +
		`id="` + c.Credential.ID + `"` +
		", " +
		`ts="` + strconv.FormatInt(c.Option.TimeStamp, 10) + `"` +
		", " +
		`nonce="` + c.Option.Nonce + `"`
	if c.Option.Hash != "" {
		header = header + ", " + `hash="` + c.Option.Hash + `"`
	}
	if c.Option.Ext != "" {
		header = header + ", " + `ext="` + c.Option.Ext + `"`
	}
	header = header + ", " + `mac="` + mac + `"`
	if c.Option.App != "" {
		header = header + ", " + `app="` + c.Option.App + `"`
		if c.Option.Dlg != "" {
			header = header + ", " + `dlg="` + c.Option.Dlg + `"`
		}
	}

	return header, nil
}

func (c *Client) Authenticate(res *http.Response) error {
	artifacts := *c.Option

	wah := res.Header.Get("WWW-Authenticate")
	if wah != "" {
		// TODO: validate WWW-Authenticate Header
	}

	sah := res.Header.Get("Server-Authorization")
	serverAuthAttributes := parseHawkHeader(sah)

	artifacts.Ext = serverAuthAttributes["ext"]
	artifacts.Hash = serverAuthAttributes["hash"]

	m := &Mac{
		Type: Response,
		Credential: c.Credential,
		Uri: res.Request.URL.String(),
		Method: res.Request.Method,
		Option: &artifacts,
	}

	mac, err := m.String()
	if err != nil {
		return err
	}
	if mac != serverAuthAttributes["mac"] {
		return errors.New("Bad response mac")
	}

	if c.Option.Payload == "" {
		return nil
	}

	if serverAuthAttributes["hash"] == "" {
		return errors.New("Missing response hash attribute")
	}

	ph := &PayloadHash{
		ContentType: res.Header.Get("Content-Type"),
		Payload: c.Option.Payload,
		Alg: c.Credential.Alg,
	}
	if ph.String() != serverAuthAttributes["hash"] {
		return errors.New("Bad response payload mac")
	}

	return nil
}

func Nonce(n int) (string, error) {
	bytes := make([]byte, n)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func parseHawkHeader(headerVal string) map[string]string {
	attrs := make(map[string]string)

	hv  := strings.Split(strings.Split(headerVal, "Hawk ")[1], ", ")

	for _, v := range hv {
		r := regexp.MustCompile(`(\w+)="([^"\\]*)"\s*(?:,\s*|$)`)
		group := r.FindSubmatch([]byte(v))
		attrs[string(group[1])] = string(group[2])
	}

	return attrs
}
