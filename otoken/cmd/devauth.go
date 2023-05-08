package cmd

import (
	"golang.org/x/oauth2"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/spf13/cobra"
	"github.com/tiewei/gopack/otoken/pkg/devauth"
	"github.com/tiewei/gopack/otoken/pkg/openid"
)

func addDevAuth(cmd *cobra.Command) {
	var cachePath string
	var noCache bool
	var clientID string
	var issuerURI string
	var clientSecret string

	scopes := []string{}

	devAuth := &cobra.Command{
		Use:   "devAuth",
		Short: "Get oauth2 access token by using the device authorization (RFC8628)",
		RunE: func(cmd *cobra.Command, args []string) error {
			endpoint, err := openid.Discover(cmd.Context(), issuerURI)
			if err != nil {
				return err
			}
			var src oauth2.TokenSource

			src = devauth.NewTokenSource(endpoint.DeviceAuthURL, endpoint.TokenURL, clientID, scopes)
			if !noCache {
				src = cachedSource(src, endpoint.TokenURL, clientID, cachePath)
			}

			token, err := src.Token()
			if err != nil {
				return err
			}
			cmd.Print(token)
			return nil
		},
	}
	devAuth.Flags().StringVarP(&cachePath, "store", "s", "~/.otoken", "path to store the token")
	// nolint:errcheck
	devAuth.MarkFlagDirname("store")
	devAuth.Flags().BoolVar(&noCache, "no-cache", false, "flag to avoid the token cache")
	devAuth.MarkFlagsMutuallyExclusive("store", "no-cache")

	devAuth.Flags().StringVarP(&clientID, "client-id", "c", "", "OAuth2 client ID")
	devAuth.Flags().StringVarP(&issuerURI, "issuer", "i", "", "OAuth2 issuer URI")
	// nolint:errcheck
	devAuth.MarkFlagRequired("client-id")
	// nolint:errcheck
	devAuth.MarkFlagRequired("issuer")
	devAuth.Flags().StringVarP(&clientSecret, "client-secret", "p", "", "OAuth2 client secret (required when use implicit flow), if empty, will use env $OTOKEN_SECRET")

	devAuth.Flags().StringArrayVar(&scopes, "scopes", []string{gooidc.ScopeOpenID, gooidc.ScopeOfflineAccess}, "scope used to request new token")

	cmd.AddCommand(devAuth)
}
