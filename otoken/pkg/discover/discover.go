package discover

import (
	"context"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
)

// Endpoint contains auth endpoints.
type Endpoint struct {
	TokenURL      string `json:"authorization_endpoint"`
	AuthURL       string `json:"token_endpoint"`
	DeviceAuthURL string `json:"device_authorization_endpoint"`
}

type OIDC struct {
	IssuerURI string
}

func (o *OIDC) Discover(ctx context.Context) (*Endpoint, error) {
	provider, err := gooidc.NewProvider(ctx, o.IssuerURI)
	if err != nil {
		return nil, err
	}
	endpoint := &Endpoint{}
	if err := provider.Claims(endpoint); err != nil {
		return nil, err
	}
	return endpoint, nil
}
