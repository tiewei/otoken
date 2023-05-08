package cmd

import (
	"errors"
	"os"

	"golang.org/x/oauth2"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/spf13/cobra"
	"github.com/tiewei/gopack/otoken/pkg/appauth"
	"github.com/tiewei/gopack/otoken/pkg/openid"
)

func addAppAuth(cmd *cobra.Command) {
	var cachePath string
	var noCache bool
	var clientID string
	var issuerURI string
	var clientSecret string

	var usePKCE bool
	var useImplicit bool

	scopes := []string{}

	appAuth := &cobra.Command{
		Use:   "appAuth",
		Short: "Get oauth2 access token by using the native app authorization (RFC8252)",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if clientSecret == "" {
				clientSecret = os.Getenv("OTOKEN_SECRET")
			}
			if clientSecret == "" && useImplicit {
				return errors.New("client-secret is required when using implicit flow")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			endpoint, err := openid.Discover(cmd.Context(), issuerURI)
			if err != nil {
				return err
			}
			var src oauth2.TokenSource

			if useImplicit {
				src = appauth.NewImplicit(endpoint.AuthURL, endpoint.TokenURL, clientID, clientSecret, scopes)
			} else if usePKCE {
				src = appauth.NewPKCE(endpoint.AuthURL, endpoint.TokenURL, clientID, scopes)
			} else {
				return errors.New("Unknown grant flow, must choose implicit or PKCE")
			}

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
	appAuth.Flags().StringVarP(&cachePath, "store", "s", "~/.otoken", "path to store the token")
	// nolint:errcheck
	appAuth.MarkFlagDirname("store")
	appAuth.Flags().BoolVar(&noCache, "no-cache", false, "flag to avoid the token cache")
	appAuth.MarkFlagsMutuallyExclusive("store", "no-cache")

	appAuth.Flags().StringVarP(&clientID, "client-id", "c", "", "OAuth2 client ID")
	appAuth.Flags().StringVarP(&issuerURI, "issuer", "i", "", "OAuth2 issuer URI")
	// nolint:errcheck
	appAuth.MarkFlagRequired("client-id")
	// nolint:errcheck
	appAuth.MarkFlagRequired("issuer")
	appAuth.Flags().StringVarP(&clientSecret, "client-secret", "p", "", "OAuth2 client secret (required when use implicit flow), if empty, will use env $OTOKEN_SECRET")

	appAuth.Flags().BoolVar(&usePKCE, "pkce", false, "use native app PKCE grant flow")
	appAuth.Flags().BoolVar(&useImplicit, "implicit", false, "use native app implicit grant flow")
	appAuth.MarkFlagsMutuallyExclusive("pkce", "implicit")
	appAuth.Flags().StringArrayVar(&scopes, "scopes", []string{gooidc.ScopeOpenID, gooidc.ScopeOfflineAccess}, "scope used to request new token")

	cmd.AddCommand(appAuth)
}
