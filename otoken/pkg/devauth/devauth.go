package devauth

// Package devauth implements the OAuth2 device authorization
// grant process described in rfc8628.
//
// The Authorizor will require device authorization endpoints,
// client id, and scopes. First call RequestCode to get UserCodeURI,
// which contains user code and verification URI for user to visit.
// While the user is completing the web flow, call PollToken, which blocks
// the goroutine until the user has authorized the app on the server.
//
// The TokenSource implements oauth2.TokenSource interface for device
// authorization grant.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tiewei/gopack/otoken/pkg/openid"
	"golang.org/x/oauth2"
)

// expirationTime is internal type to avoid time value overflow
type expirationTime int32

func (e *expirationTime) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	var n json.Number
	err := json.Unmarshal(b, &n)
	if err != nil {
		return err
	}
	i, err := n.Int64()
	if err != nil {
		return err
	}
	if i > math.MaxInt32 {
		i = math.MaxInt32
	}
	*e = expirationTime(i)
	return nil
}

// UserCodeURI is the information user needed to verify the device
type UserCodeURI struct {
	// The end-user verification code.
	UserCode string `json:"user_code"`

	// The end-user verification URI on the authorization server.
	VerificationURI string `json:"verification_uri"`

	// A verification URI that includes the "user_code".
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
}

// deviceCodeResponse holds information about the device auth flow
// https://datatracker.ietf.org/doc/html/rfc8628#section-3.2
type deviceCodeResponse struct {
	UserCodeURI

	// The device verification code.
	DeviceCode string `json:"device_code"`

	// The lifetime in seconds of the "device_code" and "user_code".
	// The number of seconds that this set of values is valid.
	// After the device code and user code expire, the user has to start the device verification process over.
	ExpiresIn expirationTime `json:"expires_in,omitempty"`

	// The minimum amount of time in seconds that the client SHOULD wait between polling requests to the token endpoint.
	Interval expirationTime `json:"interval,omitempty"`
}

type tokenRaw struct {
	AccessToken  string         `json:"access_token"`
	TokenType    string         `json:"token_type"`
	RefreshToken string         `json:"refresh_token"`
	ExpiresIn    expirationTime `json:"expires_in"`
}

type tokenErrResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// Authorizor implements device authorization flow
type Authorizor struct {
	tokenEndpoint string
	authEndpoint  string
	clientID      string
	scopes        []string
	authResp      *deviceCodeResponse
}

// New creates a new Authorizor instance from Endpoint, clientID and scopes
func New(tokenEndpoint string, authEndpoint string, clientID string, scopes []string) *Authorizor {
	return &Authorizor{
		tokenEndpoint: tokenEndpoint,
		authEndpoint:  authEndpoint,
		clientID:      clientID,
		scopes:        openid.EnsureOpenIDScope(scopes),
	}
}

// RequestCode requests device authorization endpoint to authorization codes
func (d *Authorizor) RequestCode(ctx context.Context, client *http.Client) (*UserCodeURI, error) {
	resp, err := client.PostForm(d.authEndpoint, url.Values{
		"client_id": {d.clientID},
		"scope":     {strings.Join(d.scopes, " ")},
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to request device code: response code %d, %s", resp.StatusCode, string(body))
	}

	data := &deviceCodeResponse{}
	if err := json.NewDecoder(resp.Body).Decode(data); err != nil {
		return nil, err
	}
	if data.DeviceCode == "" || data.UserCode == "" || data.VerificationURI == "" || data.ExpiresIn <= 0 {
		return nil, fmt.Errorf("%#v is not a valid device code response", data)
	}
	d.authResp = data
	if d.authResp.Interval == 0 {
		d.authResp.Interval = 5
	}
	return &UserCodeURI{
		UserCode:                d.authResp.UserCode,
		VerificationURI:         d.authResp.VerificationURI,
		VerificationURIComplete: d.authResp.VerificationURIComplete,
	}, nil
}

const deviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"

// PollToken polls the server from token endpoint until an access token is granted or denied.
func (d *Authorizor) PollToken(ctx context.Context, client *http.Client) (*oauth2.Token, error) {
	ctx, cancelFn := context.WithTimeout(ctx, time.Duration(d.authResp.ExpiresIn)*time.Second)
	defer cancelFn()
	ticker := time.NewTicker(time.Duration(d.authResp.Interval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, errors.New("timeout polling device token")
		case <-ticker.C:
			resp, err := client.PostForm(d.tokenEndpoint, url.Values{
				"client_id":   {d.clientID},
				"device_code": {d.authResp.DeviceCode},
				"grant_type":  {deviceGrantType},
			})
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()
			data := struct {
				tokenRaw
				tokenErrResponse
			}{}

			if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
				return nil, err
			} else if data.tokenRaw.AccessToken != "" {
				return &oauth2.Token{
					AccessToken:  data.tokenRaw.AccessToken,
					RefreshToken: data.tokenRaw.RefreshToken,
					TokenType:    data.tokenRaw.TokenType,
					Expiry:       time.Now().Add(time.Duration(data.tokenRaw.ExpiresIn) * time.Second),
				}, nil
			} else if data.tokenErrResponse.Error != "authorization_pending" {
				return nil, errors.New(data.tokenErrResponse.ErrorDescription)
			}
		}
	}
}
