package core

import (
	"log"
	"net/http"
)

// ReplaceAuthHeader injects the latest ServiceAccount token into the request.
// This ensures all manual API calls use the rotated token instead of a old / expired token.
func ReplaceAuthHeader(req *http.Request, provider TokenProvider) {
	if provider == nil || req == nil {
		return
	}

	// fetch token from the cache (auto-refreshes on rotation)
	tok, err := provider.Get()
	if err != nil {
		log.Printf("failed to get token: %v", err)
	}

	// only set header when a valid token is available
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
}
