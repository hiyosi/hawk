package hawk

import (
	"encoding/base64"
	"errors"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Server struct {
	CredentialStore  CredentialStore
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
	CustomURIHeader      string
}

type CredentialStore interface {
	GetCredential(id string) (*Credential, error)
}

type NonceValidator interface {
	Validate(key, nonce string, ts int64) bool
}

// NewServer initializies a new Server.
func NewServer(cs CredentialStore) *Server {
	return &Server{
		CredentialStore: cs,
	}
}

// Authenticate authenticate the Hawk request from the HTTP request.
// Successful case returns credential information about requested user.
func (s *Server) Authenticate(req *http.Request) (*Credential, error) {
	// 0 is treated as empty. set to default value.
	if s.TimeStampSkew == 0 {
		s.TimeStampSkew = 60 * time.Second
	}

	clock := getClock(s.AuthOption)
	now := clock.Now(s.LocaltimeOffset)

	authzHeader := req.Header.Get("Authorization")
	if authzHeader == "" {
		return nil, errors.New("Authorization header not found.")
	}
	authzAttributes := parseHawkHeader(authzHeader)
	if authzAttributes["id"] == "" || authzAttributes["ts"] == "" ||
		authzAttributes["nonce"] == "" || authzAttributes["mac"] == "" {
		return nil, errors.New("Missing attributes.")
	}

	ts, err := strconv.ParseInt(authzAttributes["ts"], 10, 64)
	if err != nil {
		return nil, errors.New("Invalid ts value.")
	}

	artifacts := &Option{
		TimeStamp: ts,
		Nonce:     authzAttributes["nonce"],
		Hash:      authzAttributes["hash"],
		Ext:       authzAttributes["ext"],
		App:       authzAttributes["app"],
		Dlg:       authzAttributes["dlg"],
	}

	cred, err := s.CredentialStore.GetCredential(authzAttributes["id"])
	if err != nil {
		// FIXME: logging error
		return nil, errors.New("Failed to get Credential.")
	}
	if cred.Key == "" {
		return nil, errors.New("Invalid Credential.")
	}

	host := req.Host
	uri := req.URL.String()
	if s.AuthOption != nil {
		// set to custom host(and port) value
		if s.AuthOption.CustomHostNameHeader != "" {
			host = req.Header.Get(s.AuthOption.CustomHostNameHeader)
		}
		if s.AuthOption.CustomHostPort != "" {
			// forces override a value.
			host = s.AuthOption.CustomHostPort
		}
		if s.AuthOption.CustomURIHeader != "" {
			uri = req.Header.Get(s.AuthOption.CustomURIHeader)
			host = "" // make sure the host value is derived from the custom uri.
		}
	}

	m := &Mac{
		Type:       Header,
		Credential: cred,
		Uri:        uri,
		Method:     req.Method,
		HostPort:   host,
		Option:     artifacts,
	}
	mac, err := m.String()
	if err != nil {
		//FIXME: logging error
		return nil, errors.New("Failed to calculate MAC.")
	}

	if !fixedTimeComparison(mac, authzAttributes["mac"]) {

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
	if math.Abs(float64((artifacts.TimeStamp)-(now))) > s.TimeStampSkew.Seconds() {
		//FIXME: logging timestamp
		return nil, errors.New("Stale timestamp")
	}

	return cred, nil
}

// AuthenticateBewit authenticate the Hawk bewit request from the HTTP request.
// Successful case returns credential information about requested user.
func (s *Server) AuthenticateBewit(req *http.Request) (*Credential, error) {
	clock := getClock(s.AuthOption)
	now := clock.Now(s.LocaltimeOffset)

	encodedBewit := req.URL.Query().Get("bewit")
	if encodedBewit == "" {
		return nil, errors.New("Empty bewit.")
	}

	if req.Method != "GET" && req.Method != "HEAD" {
		return nil, errors.New("Invalid method.")
	}

	if req.Header.Get("Authorization") != "" {
		return nil, errors.New("Multiple authentications")
	}

	rawBewit, err := base64.RawURLEncoding.DecodeString(encodedBewit)
	if err != nil {
		return nil, errors.New("Failed to decode bewit parameter.")
	}

	parsedBewit := strings.Split(string(rawBewit), "\\")
	if len(parsedBewit) != 4 {
		return nil, errors.New("Invalid bewit structure.")
	}

	bewit := map[string]string{
		"id":  parsedBewit[0],
		"exp": parsedBewit[1],
		"mac": parsedBewit[2],
		"ext": parsedBewit[3],
	}

	if bewit["id"] == "" || bewit["exp"] == "" || bewit["mac"] == "" {
		return nil, errors.New("Missing bewit attributes.")
	}

	ts, err := strconv.ParseInt(bewit["exp"], 10, 64)
	if err != nil {
		return nil, errors.New("Invalid ts value.")
	}

	if ts <= now {
		return nil, errors.New("Access expired.")
	}

	cred, err := s.CredentialStore.GetCredential(bewit["id"])
	if err != nil {
		// FIXME: logging error
		return nil, errors.New("Failed to get Credential.")
	}
	if cred.Key == "" {
		return nil, errors.New("Invalid Credential.")
	}

	removedBewitURL := removeBewitParam(req.URL)

	host := req.Host
	uri := removedBewitURL.String()
	if s.AuthOption != nil {
		// set to custom host(and port) value
		if s.AuthOption.CustomHostNameHeader != "" {
			host = req.Header.Get(s.AuthOption.CustomHostNameHeader)
		}
		if s.AuthOption.CustomHostPort != "" {
			// forces override a value.
			host = s.AuthOption.CustomHostPort
		}
		if s.AuthOption.CustomURIHeader != "" {
			u, _ := url.Parse(req.Header.Get(s.AuthOption.CustomURIHeader))
			tempUri := removeBewitParam(u)
			uri = tempUri.String()
		}
	}

	m := &Mac{
		Type:       Bewit,
		Credential: cred,
		Uri:        uri,
		Method:     req.Method,
		HostPort:   host,
		Option: &Option{
			TimeStamp: ts,
			Nonce:     "",
			Ext:       bewit["ext"],
		},
	}
	mac, err := m.String()
	if err != nil {
		//FIXME: logging error
		return nil, errors.New("Failed to calculate MAC.")
	}

	if !fixedTimeComparison(mac, bewit["mac"]) {
		return nil, errors.New("Bad mac.")
	}

	return cred, nil
}

// Header builds a value to be set in the Server-Authorization header.
func (s *Server) Header(req *http.Request, cred *Credential, opt *Option) (string, error) {
	authzHeader := req.Header.Get("Authorization")
	authzAttributes := parseHawkHeader(authzHeader)

	if opt.Hash == "" && opt.ContentType != "" {
		ph := &PayloadHash{
			ContentType: opt.ContentType,
			Payload:     opt.Payload,
			Alg:         cred.Alg,
		}
		opt.Hash = ph.String()
	}

	ts, err := strconv.ParseInt(authzAttributes["ts"], 10, 64)
	if err != nil {
		return "", errors.New("Invalid ts value.")
	}
	artifacts := &Option{
		TimeStamp: ts,
		Nonce:     authzAttributes["nonce"],
		Hash:      opt.Hash,
		Ext:       opt.Ext,
		App:       authzAttributes["app"],
		Dlg:       authzAttributes["dlg"],
	}

	host := req.Host
	uri := req.URL.String()
	if s.AuthOption != nil {
		// set to custom host(and port) value
		if s.AuthOption.CustomHostNameHeader != "" {
			host = req.Header.Get(s.AuthOption.CustomHostNameHeader)
		}
		if s.AuthOption.CustomHostPort != "" {
			// forces override a value.
			host = s.AuthOption.CustomHostPort
		}
		if s.AuthOption.CustomURIHeader != "" {
			uri = req.Header.Get(s.AuthOption.CustomURIHeader)
		}
	}

	m := &Mac{
		Type:       Response,
		Credential: cred,
		Uri:        uri,
		Method:     req.Method,
		HostPort:   host,
		Option:     artifacts,
	}

	mac, err := m.String()
	if err != nil {
		//FIXME: logging error
		return "", errors.New("Failed to calculate MAC.")
	}

	header := "Hawk " + `mac="` + mac + `"`

	if opt.Hash != "" {
		header = header + ", " + `hash="` + opt.Hash + `"`
	}

	if opt.Ext != "" {
		header = header + ", " + `ext="` + opt.Ext + `"`
	}

	return header, nil
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

func removeBewitParam(u *url.URL) url.URL {
	removedQuery := &url.Values{}
	for key, _ := range u.Query() {
		if key == "bewit" {
			continue
		}
		removedQuery.Add(key, u.Query().Get(key))
	}
	removedUrl := *u
	removedUrl.RawQuery = removedQuery.Encode()

	return removedUrl
}
