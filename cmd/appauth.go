package cmd

import (
	"encoding/json"
	"errors"
	"os"

	"golang.org/x/oauth2"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/spf13/cobra"
	"github.com/tiewei/otoken/pkg/appauth"
	"github.com/tiewei/otoken/pkg/openid"
	"github.com/tiewei/otoken/pkg/types"
)

func addAppAuth(cmd *cobra.Command) {
	var cachePath string
	var noCache bool
	var clientID string
	var issuerURI string
	var clientSecret string
	var redirectHostname string
	var bindAddress string
	var noBrowser bool
	var usePKCE bool

	scopes := []string{}

	appAuth := &cobra.Command{
		Use:   "app-auth",
		Short: "Get oauth2 access token by using the native app authorization (RFC8252)",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if clientSecret == "" {
				clientSecret = os.Getenv("OTOKEN_SECRET")
			}
			if clientSecret == "" && !usePKCE {
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

			var opts []appauth.Option

			if bindAddress != "" {
				opts = append(opts, appauth.UseBindAddress([]string{bindAddress}))
			}

			if redirectHostname != "" {
				opts = append(opts, appauth.UseRedirectHostname(redirectHostname))
			}

			if noBrowser {
				opts = append(opts, appauth.UseURLOpener(types.PromptOpener(types.StdoutPrompter)))
			}

			if usePKCE {
				src = appauth.NewPKCE(endpoint.AuthURL, endpoint.TokenURL, clientID, scopes, opts...)
			} else {
				src = appauth.NewImplicit(endpoint.AuthURL, endpoint.TokenURL, clientID, clientSecret, scopes, opts...)
			}

			if !noCache {
				src = cachedSource(src, endpoint.TokenURL, clientID, cachePath)
			}

			token, err := src.Token()
			if err != nil {
				return err
			}
			data, _ := json.MarshalIndent(token, "", "    ")
			cmd.Print(string(data))
			return nil
		},
	}
	appAuth.Flags().StringVarP(&cachePath, "store", "s", "~/.otoken", "path to store the token")
	// nolint:errcheck
	appAuth.MarkFlagDirname("store")
	appAuth.Flags().BoolVar(&noCache, "no-cache", false, "flag to avoid the token cache")
	appAuth.Flags().BoolVar(&noBrowser, "no-browser", false, "flag to prevent opening URL in browser")
	appAuth.MarkFlagsMutuallyExclusive("store", "no-cache")

	appAuth.Flags().StringVarP(&clientID, "client-id", "c", "", "OAuth2 client ID")
	appAuth.Flags().StringVarP(&issuerURI, "issuer", "i", "", "OAuth2 issuer URI")
	// nolint:errcheck
	appAuth.MarkFlagRequired("client-id")
	// nolint:errcheck
	appAuth.MarkFlagRequired("issuer")
	appAuth.Flags().StringVarP(&clientSecret, "client-secret", "p", "", "OAuth2 client secret (required when use implicit flow), if empty, will use env $OTOKEN_SECRET")

	appAuth.Flags().BoolVar(&usePKCE, "pkce", false, "use native app PKCE grant flow")
	appAuth.Flags().StringArrayVar(&scopes, "scopes", []string{gooidc.ScopeOpenID, gooidc.ScopeOfflineAccess}, "scope used to request new token")

	appAuth.Flags().StringVarP(&redirectHostname, "redirect-hostname", "r", "127.0.0.1", "The RFC8252 requires 127.0.0.1 address to for safety reason, user can set this if the provider does not accept 127.0.0.1 as redirect url")
	appAuth.Flags().StringVarP(&bindAddress, "bind", "b", "", "Provides a way to bind local server on pre-configured addresses. The RFC8252 requires port to be any port when using loopback interface redirection, hence the default behavior is using first free port and 127.0.0.1 address")

	cmd.AddCommand(appAuth)
}
