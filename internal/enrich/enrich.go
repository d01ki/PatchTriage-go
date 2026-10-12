// Package enrich attaches authoritative, deterministic evidence (EPSS, CISA
// KEV, CISA Vulnrichment, NVD and vendor advisories) to findings. Values are
// fetched, never generated; failures are recorded, never read as absence.
package enrich

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	entryCacheSchema = "patchtriage-entry-cache-v1"
	// MaxResponseBytes bounds every provider response.
	MaxResponseBytes = 32 << 20
)

var cacheLock sync.Mutex

// DefaultCacheDir honors PATCHTRIAGE_CACHE_DIR, else ~/.cache/patchtriage-go
// (kept apart from the Python implementation's cache).
func DefaultCacheDir() string {
	if dir := os.Getenv("PATCHTRIAGE_CACHE_DIR"); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "patchtriage-go-cache")
	}
	return filepath.Join(home, ".cache", "patchtriage-go")
}

func atomicWriteJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if _, err := temp.Write(raw); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(temp.Name(), path)
}

type cacheEntry struct {
	Value     json.RawMessage `json:"value"`
	FetchedAt float64         `json:"fetched_at"`
}

func isObject(raw json.RawMessage) bool {
	var fields map[string]json.RawMessage
	return json.Unmarshal(raw, &fields) == nil && fields != nil
}

// decodeEntryCache normalizes timestamped and legacy (value-only) caches.
func decodeEntryCache(raw []byte, fallback float64) map[string]cacheEntry {
	entries := map[string]cacheEntry{}
	var top map[string]json.RawMessage
	if json.Unmarshal(raw, &top) != nil {
		return entries
	}
	var schema string
	_ = json.Unmarshal(top["_schema"], &schema)
	if schema == entryCacheSchema {
		var wrapped map[string]json.RawMessage
		if json.Unmarshal(top["entries"], &wrapped) != nil {
			return entries
		}
		for key, item := range wrapped {
			var entry struct {
				Value     json.RawMessage `json:"value"`
				FetchedAt *float64        `json:"fetched_at"`
			}
			if json.Unmarshal(item, &entry) == nil && entry.FetchedAt != nil && isObject(entry.Value) {
				entries[key] = cacheEntry{entry.Value, *entry.FetchedAt}
			}
		}
		return entries
	}
	for key, value := range top {
		if isObject(value) {
			entries[key] = cacheEntry{value, fallback}
		}
	}
	return entries
}

func unixSeconds(t time.Time) float64 { return float64(t.UnixNano()) / 1e9 }

// LoadEntryCache returns the per-record cache entries younger than maxAge.
func LoadEntryCache(dir, name string, maxAge time.Duration) map[string]json.RawMessage {
	path := filepath.Join(dir, name)
	cacheLock.Lock()
	info, statErr := os.Stat(path)
	raw, readErr := os.ReadFile(path)
	cacheLock.Unlock()
	values := map[string]json.RawMessage{}
	if statErr != nil || readErr != nil {
		return values
	}
	cutoff := unixSeconds(time.Now().Add(-maxAge))
	for key, entry := range decodeEntryCache(raw, unixSeconds(info.ModTime())) {
		if entry.FetchedAt >= cutoff {
			values[key] = entry.Value
		}
	}
	return values
}

// MergeEntryCache atomically merges successful records with fetch times.
func MergeEntryCache(dir, name string, updates map[string]json.RawMessage) error {
	if len(updates) == 0 {
		return nil
	}
	path := filepath.Join(dir, name)
	cacheLock.Lock()
	defer cacheLock.Unlock()
	fallback := unixSeconds(time.Now())
	if info, err := os.Stat(path); err == nil {
		fallback = unixSeconds(info.ModTime())
	}
	raw, _ := os.ReadFile(path)
	entries := decodeEntryCache(raw, fallback)
	now := unixSeconds(time.Now())
	for key, value := range updates {
		if isObject(value) {
			entries[key] = cacheEntry{value, now}
		}
	}
	return atomicWriteJSON(path, map[string]any{"_schema": entryCacheSchema, "entries": entries})
}

// StatusError reproduces httpx's raise_for_status message so recorded
// errors read the same as the Python implementation's.
func StatusError(resp *http.Response) error {
	if resp.StatusCode < 400 {
		return nil
	}
	kind := "Client error"
	if resp.StatusCode >= 500 {
		kind = "Server error"
	}
	return fmt.Errorf("%s '%d %s' for url '%s'\nFor more information check: "+
		"https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/%d",
		kind, resp.StatusCode, http.StatusText(resp.StatusCode), resp.Request.URL, resp.StatusCode)
}

// ReadBody reads a response body bounded by MaxResponseBytes.
func ReadBody(resp *http.Response) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxResponseBytes {
		return nil, fmt.Errorf("response from %s exceeds %d bytes", resp.Request.URL, MaxResponseBytes)
	}
	return raw, nil
}
