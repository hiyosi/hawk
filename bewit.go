package hawk

import (
	"encoding/base64"
	"strconv"
	"time"
)

type BewitConfig struct {
	Credential          *Credential
	TtlSec              int64
	Ext                 string
	LocalTimeOffsetMsec int64
}

type Clock interface {
	Now() int64
}
type LocalClock struct{}

func (c *LocalClock) Now() int64 {
	return time.Now().Unix()
}

// TODO: Implement the SNTP for time sync management

func (b *BewitConfig) GetBewit(url string, clock Clock) string {
	if url == "" {
		return ""
	}
	if b.Credential.ID == "" || b.Credential.Key == "" || b.Credential.Alg == 0 {
		return ""
	}

	if clock == nil {
		clock = &LocalClock{}
	}
	now := clock.Now() + b.LocalTimeOffsetMsec
	exp := now + b.TtlSec

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

	return base64.URLEncoding.EncodeToString([]byte(bewit))
}
