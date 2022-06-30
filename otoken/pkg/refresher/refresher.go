package refresher

import (
	"context"
	"errors"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

type TokenRefresher struct {
	cfg           *oauth2.Config
	refreshClient *http.Client
}

// Option configures optional field for TokenRefresher,
// it's an interface with private function, hence can
// only be created within the pkg.
type Option interface {
	apply(*TokenRefresher)
}

type option struct {
	applyFunc func(*TokenRefresher)
}

func (o option) apply(t *TokenRefresher) {
	o.applyFunc(t)
}

// UseHTTPClient sets http client used to make http requests.
func UseHTTPClient(c *http.Client) Option {
	return &option{applyFunc: func(t *TokenRefresher) {
		t.refreshClient = c
	}}
}

// New creates a new refresher TokenSource
func New(tokenURL string, clientID string, clientSecret string, opts ...Option) *TokenRefresher {
	ts := &TokenRefresher{
		cfg: &oauth2.Config{
			Endpoint: oauth2.Endpoint{
				TokenURL: tokenURL,
			},
			ClientID:     clientID,
			ClientSecret: clientSecret,
		},
	}
	for _, op := range opts {
		if op != nil {
			op.apply(ts)
		}
	}

	return ts
}

func (r *TokenRefresher) Refresh(refreshToken string) (*oauth2.Token, error) {
	if refreshToken == "" {
		return nil, errors.New("no refresh token provided")
	}
	currentToken := &oauth2.Token{
		Expiry:       time.Now().Add(-1 * time.Second),
		RefreshToken: refreshToken,
	}
	ctx := context.Background()
	if r.refreshClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, r.refreshClient)
	}
	return r.cfg.TokenSource(ctx, currentToken).Token()
}

type TokenSource struct {
	refresher    *TokenRefresher
	refreshToken string
}

func NewTokenSource(tokenURL string, clientID string, clientSecret string, refreshToken string, opts ...Option) *TokenSource {
	return &TokenSource{
		refresher:    New(tokenURL, clientID, clientSecret, opts...),
		refreshToken: refreshToken,
	}
}

// refresher.TokenSource creates a new token by using the refresh token grant flow.
func (t *TokenSource) Token() (*oauth2.Token, error) {
	token, err := t.refresher.Refresh(t.refreshToken)
	if token != nil && token.RefreshToken != "" {
		t.refreshToken = token.RefreshToken
	}
	return token, err
}
