// Package userauth implements the OAuth2 native app authorization
// described in rfc8252. This helps CLI client to get access token.
//
// It uses loopback device and by default uses any free port according
// to https://datatracker.ietf.org/doc/html/rfc8252#section-7.3
//
// To configure this, you'll need to add a couple of redirect URLs
// like http://127.0.0.1:<your-port> into the okta application sign-in redirect URIs.
// And use WithLocalServerBindAddress to configure the context to
// only uses ports list from your assigned list.
package appauth

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"

	"github.com/int128/oauth2cli"
	"github.com/int128/oauth2cli/oauth2params"
	"github.com/tiewei/otoken/pkg/openid"
	"github.com/tiewei/otoken/pkg/types"
)

// Option configures optional field for TokenSource,
// it's an interface with private function, hence can
// only be created within the pkg.
type Option interface {
	apply(*TokenSource)
}

type option struct {
	applyFunc func(*TokenSource)
}

func (o option) apply(s *TokenSource) {
	o.applyFunc(s)
}

// UsePrompter sets prompter for tokensource
func UsePrompter(p types.Prompter) Option {
	return &option{applyFunc: func(s *TokenSource) {
		s.prompter = p
	}}
}

// UseURLOpener sets URL opener for tokensource
func UseURLOpener(o types.URLOpener) Option {
	return &option{applyFunc: func(s *TokenSource) {
		s.opener = o
	}}
}

// UseHTTPClient sets http client used to make http requests.
func UseHTTPClient(c *http.Client) Option {
	return &option{applyFunc: func(s *TokenSource) {
		s.client = c
	}}
}

// Timeout sets additional timeout for the token polling process.
func Timeout(t time.Duration) Option {
	return &option{applyFunc: func(s *TokenSource) {
		s.timeout = t
	}}
}

// UseBindAddress provides a way to bind local server on pre-configured addresses.
//
// The RFC8252 requires port to be any port when using loopback interface redirection,
// hence the default behavior is using first free port and 127.0.0.1 address
// https://datatracker.ietf.org/doc/html/rfc8252#section-7.3
//
// In case running it in container, it will need to bind on 0.0.0.0 or other addresses.
func UseBindAddress(addresses []string) Option {
	return &option{applyFunc: func(s *TokenSource) {
		s.bindAddresses = addresses
	}}
}

// UseRedirectHostname provides a way to set redirect hostname.
//
// The RFC8252 requires 127.0.0.1 address to for safety reason.
// You can set this if your provider does not accept 127.0.0.1
func UseRedirectHostname(hostname string) Option {
	return &option{applyFunc: func(s *TokenSource) {
		s.redirectHostname = hostname
	}}
}

type TokenSource struct {
	authEndpoint  string
	tokenEndpoint string
	clientID      string
	scopes        []string
	clientSecret  string
	usePKCE       bool

	client           *http.Client
	prompter         types.Prompter
	opener           types.URLOpener
	bindAddresses    []string
	timeout          time.Duration
	redirectHostname string
}

var _ oauth2.TokenSource = &TokenSource{}

func NewPKCE(authEndpoint string, tokenEndpoint string, clientID string, scopes []string, opts ...Option) *TokenSource {
	s := &TokenSource{
		authEndpoint:  authEndpoint,
		tokenEndpoint: tokenEndpoint,
		clientID:      clientID,
		usePKCE:       true,
		scopes:        openid.EnsureOpenIDScope(scopes),

		client:           http.DefaultClient,
		prompter:         types.StdoutPrompter,
		opener:           types.BrowserOpener,
		redirectHostname: "127.0.0.1",
	}
	for _, op := range opts {
		if op != nil {
			op.apply(s)
		}
	}
	return s
}

func NewImplicit(authEndpoint string, tokenEndpoint string, clientID string, clientSecret string, scopes []string, opts ...Option) *TokenSource {
	s := &TokenSource{
		authEndpoint:  authEndpoint,
		tokenEndpoint: tokenEndpoint,
		clientID:      clientID,
		clientSecret:  clientSecret,
		scopes:        openid.EnsureOpenIDScope(scopes),

		client:           http.DefaultClient,
		prompter:         types.StdoutPrompter,
		opener:           types.BrowserOpener,
		redirectHostname: "127.0.0.1",
	}
	for _, op := range opts {
		if op != nil {
			op.apply(s)
		}
	}
	return s
}

func (s *TokenSource) Token() (*oauth2.Token, error) {
	oauth2Cfg := oauth2.Config{
		ClientID:     s.clientID,
		ClientSecret: s.clientSecret,
		Scopes:       s.scopes,
		Endpoint: oauth2.Endpoint{
			TokenURL: s.tokenEndpoint,
			AuthURL:  s.authEndpoint,
		},
	}
	readyChan := make(chan string, 1)
	config := oauth2cli.Config{
		OAuth2Config:         oauth2Cfg,
		LocalServerReadyChan: readyChan,
		RedirectURLHostname:  s.redirectHostname,
		Logf:                 log.Printf,
	}
	if len(s.bindAddresses) > 0 {
		config.LocalServerBindAddress = s.bindAddresses
	}
	if s.usePKCE {
		pkce, err := oauth2params.NewPKCE()
		if err != nil {
			return nil, err
		}
		config.AuthCodeOptions = pkce.AuthCodeOptions()
		config.TokenRequestOptions = pkce.TokenRequestOptions()
	}
	ctx := context.Background()
	if s.timeout > 0 {
		var cancelFunc context.CancelFunc
		ctx, cancelFunc = context.WithTimeout(ctx, s.timeout)
		defer cancelFunc()
	}
	if s.client != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, s.client)
	}

	var eg errgroup.Group
	var token *oauth2.Token
	eg.Go(func() error {
		select {
		case url, ok := <-readyChan:
			if !ok {
				return nil
			}
			s.opener(url)
			return nil
		case <-ctx.Done():
			return fmt.Errorf("cancelled while waiting for the local server: %w", ctx.Err())
		}
	})
	eg.Go(func() error {
		var err error
		token, err = oauth2cli.GetToken(ctx, config)
		if err != nil {
			return fmt.Errorf("could not get a token: %w", err)
		}
		return nil
	})
	if err := eg.Wait(); err != nil {
		log.Printf("authorization error: %s", err)
	}
	return token, nil
}
