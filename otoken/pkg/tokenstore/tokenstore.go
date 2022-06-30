package tokenstore

import (
	"encoding/json"
	"errors"
	"os"
	"sync"

	"github.com/tiewei/gopack/otoken/pkg/refresher"
	"golang.org/x/oauth2"
)

// Store is a TokenSource and also can Save a token
type Store interface {
	oauth2.TokenSource
	Save(*oauth2.Token) error
}

// MemStore implements `Store` interface saves token in memory
type MemStore struct {
	token *oauth2.Token
	mu    sync.Mutex
}

func (m *MemStore) Token() (*oauth2.Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.token != nil && m.token.Valid() {
		return m.token, nil
	}
	return nil, nil
}

func (m *MemStore) Save(token *oauth2.Token) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.token = token
	return nil
}

// FileStore implements `Store` interface saves token in file
type FileStore struct {
	Path string
}

func (f *FileStore) Token() (*oauth2.Token, error) {
	if f.Path == "" {
		return nil, errors.New("path must not be empty")
	}
	raw, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, err
	}
	token := &oauth2.Token{}
	err = json.Unmarshal(raw, token)
	return token, err
}

func (f *FileStore) Save(token *oauth2.Token) error {
	raw, err := json.Marshal(token)
	if err != nil {
		return err
	}
	return os.WriteFile(f.Path, raw, 0600)
}

// CachedTokenSource is a TokenSource returns token from Store as long as
//                   the token is valid, otherwise get it from `Src` source
//                   and caches into `Store`.
//
// It's similar to oauth2.ReuseTokenSource, but allows wrapping with a customized
// store.
type CachedTokenSource struct {
	Src       oauth2.TokenSource
	Store     Store
	Refresher *refresher.TokenRefresher
	mu        sync.Mutex
}

func (c *CachedTokenSource) Token() (*oauth2.Token, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var token *oauth2.Token
	var err error
	defer func() {
		if err != nil && token.Valid() {
			//nolint:errcheck
			c.Store.Save(token)
		}
	}()
	token, err = c.Store.Token()
	if err == nil {
		if token.Valid() {
			return token, nil
		}
		if token.RefreshToken != "" && c.Refresher != nil {
			token, err = c.Refresher.Refresh(token.RefreshToken)
			if err == nil {
				return token, nil
			}
		}
	}
	if c.Src != nil {
		token, err = c.Src.Token()
		return token, err
	}
	return nil, errors.New("No valid token and token source found")
}
