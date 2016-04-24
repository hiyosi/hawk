package hawk

import (
	"crypto/rand"
	"encoding/hex"
	"strconv"
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
		AuthHeader,
		c.Credential,
		uri,
		method,
		c.Option,
	}

	mac, err := m.String()
	if err != nil {
		return "", err
	}

	header := "Authorization: Hawk " +
		"id=\"" + c.Credential.ID + "\"" +
		", " +
		"ts=\"" + strconv.FormatInt(c.Option.TimeStamp, 10) + "\"" +
		", " +
		"nonce=\"" + c.Option.Nonce + "\""
	if c.Option.Hash != "" {
		header = header + ", " + "hash=\"" + c.Option.Hash + "\""
	}
	if c.Option.Ext != "" {
		header = header + ", " + "ext=\"" + c.Option.Ext + "\""
	}
	header = header + ", " + "mac=\"" + mac + "\""
	if c.Option.App != "" {
		header = header + ", " + "app=\"" + c.Option.App + "\""
		if c.Option.Dlg != "" {
			header = header + ", " + "dlg=\"" + c.Option.Dlg + "\""
		}
	}

	return header, nil
}

func Nonce(n int) (string, error) {
	bytes := make([]byte, n)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
