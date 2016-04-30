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
}

type CredentialGetter interface {
	GetCredential(id string) (*Credential, error)
}

type NonceValidator interface {
	Validate(nonce string) bool
}

func (s *Server) Authenticate(req *http.Request, clock Clock) (*Credential, error) {
	// 0 is treated as empty. set to default value.
	if s.TimeStampSkew == 0 {
		s.TimeStampSkew = 60 * time.Second
	}

	if clock == nil {
		clock = &LocalClock{}
	}
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

	m := &Mac{
		Type:       Header,
		Credential: cred,
		Uri:        req.URL.String(),
		Method:     req.Method,
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
		if !s.NonceValidator.Validate(artifacts.Nonce) {
			return nil, errors.New("Invalid nonce.")
		}
	}

	if math.Abs(float64(artifacts.TimeStamp*1000)-float64(now)) > float64(s.TimeStampSkew*1000) {
		//FIXME: logging timestamp
		return nil, errors.New("Stale timestamp")
	}

	return cred, nil
}
