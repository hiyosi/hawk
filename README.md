# hawk
[![Build Status](https://travis-ci.org/hiyosi/hawk.svg?branch=master)](https://travis-ci.org/hiyosi/hawk)
[![Coverage Status](https://coveralls.io/repos/github/hiyosi/hawk/badge.svg?branch=master)](https://coveralls.io/github/hiyosi/hawk?branch=master)
[![GoDoc](https://godoc.org/github.com/hiyosi/hawk?status.svg)](https://godoc.org/github.com/hiyosi/hawk)

Package hawk supports to use Hawk authentication scheme.

About Hawk: https://github.com/hueniverse/hawk

## Installation

```
go get github.com/hiyosi/hawk
```

## Example

***simple client / server***

```.go
// sample server
package main

import (
	"fmt"
	"time"
	"github.com/hiyosi/hawk"
	"net/http"
)

type credentialStore struct{}

func (c *credentialStore) GetCredential(id string) (*hawk.Credential, error) {
	return &hawk.Credential{
		ID:  id,
		Key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
		Alg: hawk.SHA256,
	}, nil
}

var testCredStore = &credentialStore{}

func hawkHandler(w http.ResponseWriter, r *http.Request) {
	s := hawk.NewServer(testCredStore)

	// authenticate client request
	cred, err := s.Authenticate(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", "Hawk")
		w.WriteHeader(401)
		fmt.Println(err)
		return
	}

	opt := &hawk.Option{
		TimeStamp: time.Now().Unix(),
		Ext:       "response-specific",
	}

	// build server response header
	h, _ := s.Header(r, cred, opt)

	w.Header().Set("Server-Authorization", h)
	w.WriteHeader(200)
	w.Write([]byte("Hello, " + cred.ID))
}

func main() {
	http.HandleFunc("/resource", hawkHandler)
	http.ListenAndServe(":8080", nil)
}
```

```.go
// sample client
package main

import (
	"fmt"
	"time"
	"github.com/hiyosi/hawk"
	"io/ioutil"
	"net/http"
)

func main() {
	c := hawk.NewClient(
		&hawk.Credential{
			ID:  "123456",
			Key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
			Alg: hawk.SHA256,
		},
		&hawk.Option{
			TimeStamp: time.Now().Unix(),
			Nonce:     "3hOHpR",
			Ext:       "some-app-data",
		},
	)

	// build request header
	header, _ := c.Header("GET", "http://localhost:8080/resource")
	req, _ := http.NewRequest("GET", "http://localhost:8080/resource", nil)
	req.Header.Set("Authorization", header)

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()

	// authenticate server response.
	result, err := c.Authenticate(resp)
	if err != nil {
		fmt.Println("Server Authentication Failure")
	}
	fmt.Println("Server Authentication: ", result)

	b, err := ioutil.ReadAll(resp.Body)
	if err == nil {
		fmt.Println(string(b))
	}
}
```

***build bewit parameter***

```.go
// server

	b := hawk.NewBewitConfig(
		&hawk.Credential{
			ID:  "123456",
			Key: "werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn",
			Alg: hawk.SHA256,
		},
		10 * time.Minute,
	)


	bewit := b.GetBewit("http://localhost:8080/temp/resource", nil)
	fmt.Println(bewit)

```

***authenticate bewit parameter***

```.go
// server

func hawkBewitHandler(w http.ResponseWriter, r *http.Request) {
	s := hawk.NewServer(testCredStore)

	cred, err := s.AuthenticateBewit(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", "Hawk")
		w.WriteHeader(401)
		fmt.Println(err)
		return
	}

	w.WriteHeader(200)
	w.Write([]byte("Access Allow, " + cred.ID))
}

```

***if behind a proxy, you can use an another header field or custom hostname.***

- get host-name by specified header name.

```.go
    s := hawk.NewServer(testCredStore)
	s.AuthOption = &hawk.AuthOption{
	    CustomHostNameHeader: "X-Forwarded-Host",
	}
```

- or specified hostname value yourself

```
    s := hawk.NewServer(testCredStore)
    s.AuthOption = &hawk.AuthOption{
	    CustomHostPort: "b.example.com:8888",
	}
```

See godoc for further documentation

- https://godoc.org/github.com/hiyosi/hawk

## Contribution

1. Fork ([https://github.com/hiyosi/hawk/fork](https://github.com/hiyosi/hawk/fork))
2. Create a feature branch
3. Commit your changes
4. Rebase your local changes against the master branch
5. Run test suite with the `go test ./...` command and confirm that it passes
6. Run `gofmt -s`
7. Create new Pull Request

## License
[MIT](https://github.com/hiyosi/hawk/blob/master/LICENSE)
