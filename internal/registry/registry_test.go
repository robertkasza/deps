package registry

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPClient_VersionsAndManifest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/lodash" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"name": "lodash",
			"versions": {
				"4.17.20": {"name": "lodash", "version": "4.17.20", "dependencies": {}},
				"4.17.21": {"name": "lodash", "version": "4.17.21", "dependencies": {}}
			}
		}`))
	}))
	defer srv.Close()

	c := &HTTPClient{Registry: srv.URL, cache: map[string]*packageDoc{}}

	versions, err := c.Versions("lodash")
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if len(versions) != 2 {
		t.Errorf("got %d versions, want 2", len(versions))
	}

	m, err := c.Manifest("lodash", "4.17.21")
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if m.Version != "4.17.21" {
		t.Errorf("version: got %q, want 4.17.21", m.Version)
	}

	if _, err := c.Manifest("lodash", "9.9.9"); err == nil {
		t.Errorf("expected error for unknown version")
	}
}

func TestHTTPClient_CachesAcrossCalls(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Write([]byte(`{"name":"x","versions":{"1.0.0":{"name":"x","version":"1.0.0"}}}`))
	}))
	defer srv.Close()

	c := &HTTPClient{Registry: srv.URL, cache: map[string]*packageDoc{}}
	for i := 0; i < 5; i++ {
		if _, err := c.Versions("x"); err != nil {
			t.Fatalf("Versions: %v", err)
		}
	}
	if hits != 1 {
		t.Errorf("got %d HTTP hits, want 1", hits)
	}
}

func TestHTTPClient_ScopedPackage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// RawPath preserves the URL-encoded form; Path is decoded.
		if r.URL.RawPath != "/@scope%2Fname" {
			t.Errorf("scoped package raw path: got %q, want /@scope%%2Fname", r.URL.RawPath)
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`{"name":"@scope/name","versions":{}}`))
	}))
	defer srv.Close()

	c := &HTTPClient{Registry: srv.URL, cache: map[string]*packageDoc{}}
	if _, err := c.Versions("@scope/name"); err != nil {
		t.Fatalf("Versions: %v", err)
	}
}

func TestHTTPClient_404(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	c := &HTTPClient{Registry: srv.URL, cache: map[string]*packageDoc{}}
	if _, err := c.Versions("missing"); err == nil {
		t.Errorf("expected error on 404")
	}
}
