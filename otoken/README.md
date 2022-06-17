# OToken

OToken gets OAuth client process into native app.

It contains two packages implemented [oauth2.TokenSource](https://pkg.go.dev/golang.org/x/oauth2#TokenSource),
the `appauth` implemented OAuth2 native app authorization described in RFC8252,
and the `devauth` implemented OAuth2 device authorization grant process described in RFC8628.
