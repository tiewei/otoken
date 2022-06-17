package refresher

import (
	"context"
	"errors"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

type TokenSource struct {
	cfg           *oauth2.Config
	refreshToken  string
	refreshClient *http.Client
}

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

// UseHTTPClient sets http client used to make http requests.
func UseHTTPClient(c *http.Client) Option {
	return &option{applyFunc: func(s *TokenSource) {
		s.refreshClient = c
	}}
}

// New creates a new refresher TokenSource
func New(tokenURL string, clientID string, clientSecret string, refreshToken string, opts ...Option) *TokenSource {
	ts := &TokenSource{
		cfg: &oauth2.Config{
			Endpoint: oauth2.Endpoint{
				TokenURL: tokenURL,
			},
			ClientID:     clientID,
			ClientSecret: clientSecret,
		},
		refreshToken: refreshToken,
	}
	for _, op := range opts {
		if op != nil {
			op.apply(ts)
		}
	}

	return ts
}

// refresher.TokenSource creates a new token by using the refresh token grant flow.
func (t *TokenSource) Token() (*oauth2.Token, error) {
	if t.refreshToken == "" {
		return nil, errors.New("no refresh token provided")
	}
	currentToken := &oauth2.Token{
		Expiry:       time.Now().Add(-1 * time.Second),
		RefreshToken: t.refreshToken,
	}
	ctx := context.Background()
	if t.refreshClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, t.refreshClient)
	}
	token, err := t.cfg.TokenSource(ctx, currentToken).Token()
	if token != nil && token.RefreshToken != "" {
		t.refreshToken = token.RefreshToken
	}
	return token, err
}
