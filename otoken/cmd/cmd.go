package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/spf13/cobra"
	"github.com/tiewei/gopack/otoken/pkg/appauth"
	"github.com/tiewei/gopack/otoken/pkg/devauth"
	"github.com/tiewei/gopack/otoken/pkg/openid"
	"github.com/tiewei/gopack/otoken/pkg/refresher"
	"github.com/tiewei/gopack/otoken/pkg/tokenstore"

	"golang.org/x/oauth2"
)

func New() *cobra.Command {
	var cachePath string
	var noCache bool
	var clientID string
	var issuerURI string
	var clientSecret string

	var usePKCE bool
	var useImplicit bool
	var useDevice bool
	var useRefresh bool

	scopes := []string{}

	otoken := &cobra.Command{
		Use:   "otoken",
		Short: "otken is a cli to get oauth2 access token",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if clientSecret == "" {
				clientSecret = os.Getenv("OTOKEN_SECRET")
			}
			if clientSecret == "" && useImplicit {
				return errors.New("client-secret is required when using implicit flow")
			}

			if strings.HasPrefix(cachePath, "~/") {
				home, _ := os.UserHomeDir()
				cachePath = strings.Replace(cachePath, "~", home, 1)
			}
			if strings.HasPrefix(cachePath, "./") {
				cachePath = strings.TrimLeft(cachePath, "./")
			}
			return os.MkdirAll(cachePath, 0700)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			endpoint, err := openid.Discover(cmd.Context(), issuerURI)
			if err != nil {
				return err
			}
			var src oauth2.TokenSource

			if useDevice {
				src = devauth.NewTokenSource(endpoint.DeviceAuthURL, endpoint.TokenURL, clientID, scopes)
			} else if useImplicit {
				src = appauth.NewImplicit(endpoint.AuthURL, endpoint.TokenURL, clientID, clientSecret, scopes)
			} else if usePKCE {
				src = appauth.NewPKCE(endpoint.AuthURL, endpoint.TokenURL, clientID, scopes)
			}

			if !noCache {
				cache := &tokenstore.CachedTokenSource{
					Src:   src,
					Store: &tokenstore.FileStore{Path: filepath.Join(cachePath, clientID)},
				}
				if useRefresh {
					cache.Refresher = refresher.New(endpoint.TokenURL, clientID, clientSecret)
				}
				src = cache
			}

			if src != nil {
				src = oauth2.ReuseTokenSource(nil, src)
				token, err := src.Token()
				if err != nil {
					return err
				}
				cmd.Print(token)
				return nil
			}
			return errors.New("no token source picked")
		},
	}
	otoken.Flags().StringVarP(&cachePath, "store", "s", "~/.otoken", "path to store the token")
	// nolint:errcheck
	otoken.MarkFlagDirname("store")
	otoken.Flags().BoolVar(&noCache, "no-cache", false, "flag to avoid the token cache")
	otoken.MarkFlagsMutuallyExclusive("store", "no-cache")

	otoken.Flags().StringVarP(&clientID, "client-id", "c", "", "OAuth2 client ID")
	otoken.Flags().StringVarP(&issuerURI, "issuer", "i", "", "OAuth2 issuer URI")
	// nolint:errcheck
	otoken.MarkFlagRequired("client-id")
	// nolint:errcheck
	otoken.MarkFlagRequired("issuer")
	otoken.Flags().StringVarP(&clientSecret, "client-secret", "p", "", "OAuth2 client secret (required when use implicit flow), if empty, will use env $OTOKEN_SECRET")

	otoken.Flags().BoolVar(&usePKCE, "pkce", false, "use native app PKCE grant flow")
	otoken.Flags().BoolVar(&useImplicit, "implicit", false, "use native app implicit grant flow")
	otoken.Flags().BoolVar(&useDevice, "device", false, "use device auth grant flow")
	otoken.MarkFlagsMutuallyExclusive("pkce", "implicit", "device")
	otoken.Flags().BoolVarP(&useRefresh, "refresh", "r", true, "refresh token first if possible")
	otoken.Flags().StringArrayVar(&scopes, "scopes", []string{gooidc.ScopeOpenID, gooidc.ScopeOfflineAccess}, "scope used to request new token")

	return otoken
}
