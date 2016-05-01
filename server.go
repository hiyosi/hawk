package hawk

import (
	"errors"
	"math"
	"net/http"
	"strconv"
	"time"
)

type Server struct {
	CredentialGetter CredentialGetter
	NonceValidator   NonceValidator
	TimeStampSkew    time.Duration
	LocaltimeOffset  time.Duration
	Payload          string
	AuthOption       *AuthOption
}

type AuthOption struct {
	CustomHostNameHeader string
	CustomHostPort       string
	CustomClock          Clock
}

type CredentialGetter interface {
	GetCredential(id string) (*Credential, error)
}

type NonceValidator interface {
	Validate(key, nonce string, ts int64) bool
}

func (s *Server) Authenticate(req *http.Request) (*Credential, error) {
	// 0 is treated as empty. set to default value.
	if s.TimeStampSkew == 0 {
		s.TimeStampSkew = 60 * time.Second
	}

	clock := getClock(s.AuthOption)
	now := clock.Now(s.LocaltimeOffset)

	authzHeader := req.Header.Get("Authorization")
	authAttributes := parseHawkHeader(authzHeader)

	ts, err := strconv.ParseInt(authAttributes["ts"], 10, 64)
	if err != nil {
		return nil, errors.New("Invalid ts value.")
	}

	artifacts := &Option{
		TimeStamp: ts,
		Nonce:     authAttributes["nonce"],
		Hash:      authAttributes["Hash"],
		Ext:       authAttributes["ext"],
		App:       authAttributes["app"],
		Dlg:       authAttributes["dlg"],
	}

	cred, err := s.CredentialGetter.GetCredential(authAttributes["id"])
	if err != nil {
		// FIXME: logging error
		return nil, errors.New("Failed to get Credential.")
	}
	if cred.Key == "" {
		return nil, errors.New("Invalid Credential.")
	}

	var host string
	if s.AuthOption != nil {
		// set to custom host(and port) value
		if s.AuthOption.CustomHostNameHeader != "" {
			host = req.Header.Get(s.AuthOption.CustomHostNameHeader)
		}
		if s.AuthOption.CustomHostPort != "" {
			// forces override a value.
			host = s.AuthOption.CustomHostPort
		}
	}

	m := &Mac{
		Type:       Header,
		Credential: cred,
		Uri:        req.URL.String(),
		Method:     req.Method,
		HostPort:   host,
		Option:     artifacts,
	}
	mac, err := m.String()
	if err != nil {
		//FIXME: logging error
		return nil, errors.New("Failed to calculate MAC.")
	}

	if !fixedTimeComparison(mac, authAttributes["mac"]) {
		return nil, errors.New("Bad MAC")
	}

	if s.Payload != "" {
		if artifacts.Hash == "" {
			return nil, errors.New("Missing required payload hash.")
		}

		ph := &PayloadHash{
			ContentType: req.Header.Get("Content-Type"),
			Payload:     s.Payload,
			Alg:         cred.Alg,
		}
		if !fixedTimeComparison(ph.String(), artifacts.Hash) {
			return nil, errors.New("Bad payload hash.")
		}
	}

	if s.NonceValidator != nil {
		if !s.NonceValidator.Validate(cred.Key, artifacts.Nonce, artifacts.TimeStamp) {
			return nil, errors.New("Invalid nonce.")
		}
	}

	if math.Abs(float64(artifacts.TimeStamp*1000)-float64(now)) > float64(s.TimeStampSkew*1000) {
		//FIXME: logging timestamp
		return nil, errors.New("Stale timestamp")
	}

	return cred, nil
}

func getClock(authOption *AuthOption) Clock {
	var clock Clock
	if authOption == nil || authOption.CustomClock == nil {
		clock = &LocalClock{}
	} else {
		clock = authOption.CustomClock
	}
	return clock
}
