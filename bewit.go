package hawk

import (
	"encoding/base64"
	"strconv"
	"time"
)

type BewitConfig struct {
	Credential      *Credential
	Ttl             time.Duration
	Ext             string
	LocalTimeOffset time.Duration
}

func NewBewitConfig(c *Credential, ttl time.Duration) *BewitConfig {
	return &BewitConfig{
		Credential: c,
		Ttl: ttl,
	}
}

// TODO: Implement the SNTP for time sync management

// GetBewit builds a value of bewit parameter.
func (b *BewitConfig) GetBewit(url string, clock Clock) string {
	if url == "" {
		return ""
	}
	if b.Credential == nil {
		return ""
	}
	if b.Credential.ID == "" || b.Credential.Key == "" || b.Credential.Alg == 0 {
		return ""
	}

	if clock == nil {
		clock = &LocalClock{}
	}
	now := clock.Now(b.LocalTimeOffset)
	exp := time.Unix(now, 0).Add(b.Ttl).Unix()

	opt := &Option{
		TimeStamp: exp,
		Nonce:     "",
		Ext:       b.Ext,
	}

	m := &Mac{
		Type:       Bewit,
		Credential: b.Credential,
		Uri:        url,
		Method:     "GET",
		Option:     opt,
	}
	mac, _ := m.String()

	bewit := b.Credential.ID + "\\" + strconv.FormatInt(exp, 10) + "\\" + mac + "\\" + b.Ext

	return base64.RawURLEncoding.EncodeToString([]byte(bewit))
}
