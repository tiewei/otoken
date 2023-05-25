package openid

import gooidc "github.com/coreos/go-oidc/v3/oidc"

// EnsureOpenIDScope ensures `openid` in the scopes
func EnsureOpenIDScope(scopes []string) []string {
	for _, s := range scopes {
		if s == gooidc.ScopeOpenID {
			return scopes
		}
	}
	return append(scopes, gooidc.ScopeOpenID)
}
