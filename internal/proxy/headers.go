package proxy

import (
	"net/http"
	"strings"
)

// defaultStripResponseHeaders are always stripped from upstream responses.
var defaultStripResponseHeaders = []string{"Set-Cookie", "Set-Cookie2"}

// buildStripSet merges default stripped headers with any additional configured headers.
func buildStripSet(extra []string) map[string]bool {
	set := make(map[string]bool, len(defaultStripResponseHeaders)+len(extra))
	for _, h := range defaultStripResponseHeaders {
		set[http.CanonicalHeaderKey(h)] = true
	}
	for _, h := range extra {
		set[http.CanonicalHeaderKey(h)] = true
	}
	return set
}

// stripResponseHeaders removes headers in the strip set from the header map.
func stripResponseHeaders(h http.Header, stripSet map[string]bool) {
	for key := range h {
		if stripSet[http.CanonicalHeaderKey(key)] {
			h.Del(key)
		}
	}
}

// stripRequestCookies removes Cookie headers from outbound requests.
func stripRequestCookies(h http.Header) {
	for key := range h {
		if strings.EqualFold(key, "Cookie") {
			h.Del(key)
		}
	}
}
