package devauth

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/tiewei/gopack/otoken/pkg/types"
	"golang.org/x/oauth2"
)

// TokenSource implements oauth2.TokenSource interface
// to provide token via device authorization
// grant process described in rfc8628.
type TokenSource struct {
	auth *Authorizor

	client   *http.Client
	prompter types.Prompter
	opener   types.URLOpener
	timeout  time.Duration
}

var _ oauth2.TokenSource = &TokenSource{}

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

// NewTokenSource creates a new device auth token source.
// It by default uses `http.DefaultClient` as http client
// `types.StdoutPrompter` as prompter and `types.BrowserOpener`
// as URLOpener. To change these, set Options when creating the
// instance.
func NewTokenSource(tokenEndpoint string, authEndpoint string, clientID string, scopes []string, opts ...Option) *TokenSource {
	s := &TokenSource{
		auth:     New(tokenEndpoint, authEndpoint, clientID, scopes),
		client:   http.DefaultClient,
		prompter: types.StdoutPrompter,
		opener:   types.BrowserOpener,
	}
	for _, op := range opts {
		if op != nil {
			op.apply(s)
		}
	}
	return s
}

// Token creates a new auth2.Token by going through the device auth process.
func (s *TokenSource) Token() (*oauth2.Token, error) {
	ctx := context.Background()
	if s.timeout > 0 {
		var cancelFunc context.CancelFunc
		ctx, cancelFunc = context.WithTimeout(ctx, s.timeout)
		defer cancelFunc()
	}
	userURI, err := s.auth.RequestCode(ctx, s.client)
	if err != nil {
		return nil, err
	}
	if len(userURI.VerificationURIComplete) == 0 {
		s.prompter(fmt.Sprintf("Please copy one-time code: %s", userURI.UserCode), true)
		s.opener(userURI.VerificationURI)
	} else {
		s.opener(userURI.VerificationURIComplete)
	}

	return s.auth.PollToken(ctx, s.client)
}
