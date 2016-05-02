// Package hawk provides support for Hawk authentication.
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

// Clock returns a time.
type Clock interface {
	// Now returns the current unix-time obtained by adding a offset value.
	Now(offset time.Duration) int64
}
type LocalClock struct{}

func (c *LocalClock) Now(offset time.Duration) int64 {
	return time.Now().Add(offset).Unix()
}
