package openid

import (
	"context"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
)

// Endpoint contains auth endpoints.
type Endpoint struct {
	TokenURL      string `json:"token_endpoint"`
	AuthURL       string `json:"authorization_endpoint"`
	DeviceAuthURL string `json:"device_authorization_endpoint"`
}

func Discover(ctx context.Context, IssuerURI string) (*Endpoint, error) {
	provider, err := gooidc.NewProvider(ctx, IssuerURI)
	if err != nil {
		return nil, err
	}
	endpoint := &Endpoint{}
	if err := provider.Claims(endpoint); err != nil {
		return nil, err
	}
	return endpoint, nil
}
