package hawk

import (
	"errors"
	"net/http"
	"strconv"
)

type Client struct {
	Credential *Credential
	Option     *Option
}

func NewClient(c *Credential, o *Option) *Client {
	return &Client{
		Credential: c,
		Option: o,
	}
}

//  Header builds a value to be set in the Authorization header.
func (c *Client) Header(method, uri string) (string, error) {
	if c.Option.Hash == "" && c.Option.Payload != "" && c.Option.ContentType != "" {
		ph := &PayloadHash{
			ContentType: c.Option.ContentType,
			Payload:     c.Option.Payload,
			Alg:         c.Credential.Alg,
		}
		c.Option.Hash = ph.String()
	}

	m := &Mac{
		Type:       Header,
		Credential: c.Credential,
		Uri:        uri,
		Method:     method,
		Option:     c.Option,
	}

	mac, err := m.String()
	if err != nil {
		return "", err
	}

	header := "Hawk " +
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

// Authenticate authenticate the Hawk server response from the HTTP response.
// Successful case returns true.
func (c *Client) Authenticate(res *http.Response) (bool, error) {
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
		Type:       Response,
		Credential: c.Credential,
		Uri:        res.Request.URL.String(),
		Method:     res.Request.Method,
		Option:     &artifacts,
	}

	mac, err := m.String()
	if err != nil {
		return false, err
	}
	if mac != serverAuthAttributes["mac"] {
		return false, errors.New("Bad response mac")
	}

	if c.Option.Payload == "" && c.Option.ContentType == "" {
		return true, nil
	}

	if serverAuthAttributes["hash"] == "" {
		return false, errors.New("Missing response hash attribute")
	}

	ph := &PayloadHash{
		ContentType: res.Header.Get("Content-Type"),
		Payload:     c.Option.Payload,
		Alg:         c.Credential.Alg,
	}
	if ph.String() != serverAuthAttributes["hash"] {
		return false, errors.New("Bad response payload mac")
	}

	return true, nil
}
