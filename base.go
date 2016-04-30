package hawk

import "time"

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

type Clock interface {
	Now(offset time.Duration) int64
}
type LocalClock struct{}

func (c *LocalClock) Now(offset time.Duration) int64 {
	return time.Now().Add(offset).Unix()
}
