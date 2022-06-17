# OToken

OToken gets OAuth client process into native app.

It contains a few packages implemented [oauth2.TokenSource](https://pkg.go.dev/golang.org/x/oauth2#TokenSource),

- The `appauth.TokenSource` implemented OAuth2 native app authorization described in [RFC8252](https://datatracker.ietf.org/doc/html/rfc8252)
- The `devauth.TokenSource` implemented OAuth2 device authorization grant process described in [RFC8628](https://datatracker.ietf.org/doc/html/rfc8628)
- The `refresher.TokenSource` implemented refresh grant flow described in [RFC6749](https://datatracker.ietf.org/doc/html/rfc6749#section-1.5)
- The `tokenstore.CachedTokenSource` is a TokenSource that allows you read token from a struct implemented `tokenstore.Store` interface, and save new token to
such store after created.
