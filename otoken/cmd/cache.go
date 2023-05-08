package cmd

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/tiewei/gopack/otoken/pkg/refresher"
	"github.com/tiewei/gopack/otoken/pkg/tokenstore"
	"golang.org/x/oauth2"
)

func initCache(cacheBase string) error {
	if strings.HasPrefix(cacheBase, "~/") {
		home, _ := os.UserHomeDir()
		cacheBase = strings.Replace(cacheBase, "~", home, 1)
	}
	if strings.HasPrefix(cacheBase, "./") {
		cacheBase = strings.TrimLeft(cacheBase, "./")
	}
	return os.MkdirAll(cacheBase, 0700)
}

func cachedSource(src oauth2.TokenSource, tokenURL string, clientID string, cacheBase string) oauth2.TokenSource {
	initCache(cacheBase)
	cache := &tokenstore.CachedTokenSource{
		Src:       src,
		Store:     &tokenstore.FileStore{Path: filepath.Join(cacheBase, clientID)},
		Refresher: refresher.New(tokenURL, clientID),
	}

	return oauth2.ReuseTokenSource(nil, cache)
}
