// Package registry queries the npm registry for package metadata.
//
// MVP: HTTP GET against https://registry.npmjs.org (or whatever is set in
// the user's .npmrc `registry=` line). In-process cache for the lifetime
// of one run. No auth handling for private registries yet.
package registry

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const defaultRegistry = "https://registry.npmjs.org"

// Client is the surface plan needs from the registry.
type Client interface {
	// Versions returns all published version strings for pkg.
	Versions(pkg string) ([]string, error)
	// Manifest returns the package.json metadata for a specific version.
	Manifest(pkg, version string) (Manifest, error)
}

// Manifest is the subset of an npm package manifest we care about.
type Manifest struct {
	Name             string            `json:"name"`
	Version          string            `json:"version"`
	Dependencies     map[string]string `json:"dependencies"`
	PeerDependencies map[string]string `json:"peerDependencies"`
}

// HTTPClient is the default Client. Wraps an http.Client + an in-memory cache.
type HTTPClient struct {
	Registry   string        // e.g., "https://registry.npmjs.org"
	HTTPClient *http.Client  // optional override
	cacheMu    sync.Mutex
	cache      map[string]*packageDoc // pkg -> full registry doc
}

// New returns an HTTPClient using the configured registry (from
// .npmrc if present, otherwise registry.npmjs.org).
func New() *HTTPClient {
	return &HTTPClient{
		Registry: detectRegistry(),
		cache:    map[string]*packageDoc{},
	}
}

// packageDoc is the shape of a full npm registry document.
// We only read what we need.
type packageDoc struct {
	Name     string              `json:"name"`
	Versions map[string]Manifest `json:"versions"`
}

func (c *HTTPClient) fetch(pkg string) (*packageDoc, error) {
	c.cacheMu.Lock()
	if doc, ok := c.cache[pkg]; ok {
		c.cacheMu.Unlock()
		return doc, nil
	}
	c.cacheMu.Unlock()

	base := c.Registry
	if base == "" {
		base = defaultRegistry
	}
	// Scoped packages (e.g., @scope/name) need URL-escaping of the slash.
	endpoint := base + "/" + strings.ReplaceAll(pkg, "/", "%2F")

	httpc := c.HTTPClient
	if httpc == nil {
		httpc = &http.Client{Timeout: 30 * time.Second}
	}
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("registry GET %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("registry %s: %s: %s", pkg, resp.Status, strings.TrimSpace(string(body)))
	}
	var doc packageDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode registry doc for %s: %w", pkg, err)
	}

	c.cacheMu.Lock()
	c.cache[pkg] = &doc
	c.cacheMu.Unlock()
	return &doc, nil
}

// Versions returns all published version strings for pkg.
func (c *HTTPClient) Versions(pkg string) ([]string, error) {
	doc, err := c.fetch(pkg)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(doc.Versions))
	for v := range doc.Versions {
		out = append(out, v)
	}
	return out, nil
}

// Manifest returns the manifest for a specific version.
func (c *HTTPClient) Manifest(pkg, version string) (Manifest, error) {
	doc, err := c.fetch(pkg)
	if err != nil {
		return Manifest{}, err
	}
	m, ok := doc.Versions[version]
	if !ok {
		return Manifest{}, fmt.Errorf("version %s of %s not found", version, pkg)
	}
	return m, nil
}

// detectRegistry reads the user's .npmrc files in priority order
// (project-level, user-level) and returns the first `registry=` value
// found. Falls back to the default npm registry.
func detectRegistry() string {
	for _, p := range npmrcPaths() {
		if v := readRegistry(p); v != "" {
			return strings.TrimRight(v, "/")
		}
	}
	return defaultRegistry
}

func npmrcPaths() []string {
	var paths []string
	if cwd, err := os.Getwd(); err == nil {
		paths = append(paths, filepath.Join(cwd, ".npmrc"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".npmrc"))
	}
	return paths
}

func readRegistry(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "registry") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}
