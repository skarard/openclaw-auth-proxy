package proxy

import (
	"net/http"
	"testing"
)

func TestDefaultSetCookieStripping(t *testing.T) {
	h := http.Header{}
	h.Set("Set-Cookie", "session=abc")
	h.Set("Set-Cookie2", "old=val")
	h.Set("Content-Type", "application/json")

	stripSet := buildStripSet(nil)
	stripResponseHeaders(h, stripSet)

	if h.Get("Set-Cookie") != "" {
		t.Error("Set-Cookie should be stripped")
	}
	if h.Get("Set-Cookie2") != "" {
		t.Error("Set-Cookie2 should be stripped")
	}
	if h.Get("Content-Type") != "application/json" {
		t.Error("Content-Type should pass through")
	}
}

func TestCustomHeadersAdditive(t *testing.T) {
	h := http.Header{}
	h.Set("Set-Cookie", "session=abc")
	h.Set("X-OAuth-Token", "secret")
	h.Set("X-Custom", "keep")

	stripSet := buildStripSet([]string{"X-OAuth-Token"})
	stripResponseHeaders(h, stripSet)

	if h.Get("Set-Cookie") != "" {
		t.Error("Set-Cookie should be stripped (default)")
	}
	if h.Get("X-OAuth-Token") != "" {
		t.Error("X-OAuth-Token should be stripped (custom)")
	}
	if h.Get("X-Custom") != "keep" {
		t.Error("X-Custom should pass through")
	}
}

func TestCaseInsensitiveStripping(t *testing.T) {
	h := http.Header{}
	h.Set("set-cookie", "val")
	h.Set("SET-COOKIE2", "val")

	stripSet := buildStripSet(nil)
	stripResponseHeaders(h, stripSet)

	if len(h) != 0 {
		t.Errorf("expected all headers stripped, got %v", h)
	}
}

func TestNonStrippedHeadersPassThrough(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Type", "text/html")
	h.Set("X-Request-Id", "123")
	h.Set("Authorization", "Bearer tok")

	stripSet := buildStripSet(nil)
	stripResponseHeaders(h, stripSet)

	if h.Get("Content-Type") != "text/html" {
		t.Error("Content-Type missing")
	}
	if h.Get("X-Request-Id") != "123" {
		t.Error("X-Request-Id missing")
	}
	if h.Get("Authorization") != "Bearer tok" {
		t.Error("Authorization missing")
	}
}

func TestStripRequestCookies(t *testing.T) {
	h := http.Header{}
	h.Set("Cookie", "session=abc")
	h.Set("Authorization", "Bearer tok")

	stripRequestCookies(h)

	if h.Get("Cookie") != "" {
		t.Error("Cookie should be stripped")
	}
	if h.Get("Authorization") != "Bearer tok" {
		t.Error("Authorization should remain")
	}
}
