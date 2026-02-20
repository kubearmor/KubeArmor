package core

import (
	"bytes"
	"errors"
	"io"
	"os"
	"sync/atomic"

	"golang.org/x/sync/singleflight"
)

var DefaultTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// TokenProvider is used by callers to fetch the latest SA token.
type TokenProvider interface {
	Get() (string, error)
}

// TokenCache tracks the ServiceAccount token and refreshes it
// when Kubernetes rotates the projected token file.
type TokenCache struct {
	token atomic.Value       // cached token
	mtime atomic.Value       // last file mtime
	group singleflight.Group // prevents duplicate refreshes
}

func NewTokenCache() *TokenCache {
	tc := &TokenCache{}
	tc.token.Store([]byte{})
	tc.mtime.Store(int64(0))
	return tc
}

var ErrNoToken = errors.New("No Token Available")

// readTokenFile reads the projected token file and returns (contents, mtime).
func readTokenFile(path string) ([]byte, int64, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, 0, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	b, err := io.ReadAll(f)
	if err != nil {
		return nil, 0, err
	}

	return b, st.ModTime().UnixNano(), nil
}

// Get returns the latest token.
// - If the token file changed → reload
// - If the file is temporarily unreadable → return last known good token
// - Only one goroutine performs file reads --(singleflight)
func (c *TokenCache) Get() (string, error) {
	cached := c.token.Load().([]byte)

	v, err, _ := c.group.Do("load-token", func() (interface{}, error) {
		b, m, e := readTokenFile(DefaultTokenPath)
		if e != nil {
			// fallback: use previously cached token
			if len(cached) > 0 {
				out := make([]byte, len(cached))
				copy(out, cached)
				return out, nil
			}
			return nil, e
		}

		b = bytes.TrimSpace(b)

		// no change → return cached token
		prev := c.mtime.Load().(int64)
		if prev == m && len(cached) > 0 {
			out := make([]byte, len(cached))
			copy(out, cached)
			return out, nil
		}

		// file changed → update cache
		cpy := make([]byte, len(b))
		copy(cpy, b)
		c.token.Store(cpy)
		c.mtime.Store(m)
		return cpy, nil
	})
	if err != nil {
		return "", err
	}

	out := bytes.TrimSpace(v.([]byte))
	if len(out) == 0 {
		return "", ErrNoToken
	}

	return string(out), nil
}

// tokenProviderImpl adapts TokenCache to the TokenProvider interface.
type tokenProviderImpl struct {
	cache *TokenCache
}

func (p *tokenProviderImpl) Get() (string, error) {
	return p.cache.Get()
}

// Global default provider used by in-cluster HTTP callers.
var globalTokenCache = NewTokenCache()
var GlobalTokenProvider TokenProvider = &tokenProviderImpl{cache: globalTokenCache}
