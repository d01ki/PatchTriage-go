package web

import (
	"embed"
	"net/http"
	"strings"
)

// IBM Plex Latin1 subsets from @ibm/plex-sans 1.1.0 and @ibm/plex-mono 2.5.0.
// Their SIL Open Font License is included alongside the embedded fonts.
//
//go:embed fonts/*.woff2 fonts/OFL.txt
var fontFiles embed.FS

func serveFont(w http.ResponseWriter, name string) bool {
	if strings.Contains(name, "..") || strings.ContainsAny(name, `/\`) || !strings.HasSuffix(name, ".woff2") {
		return false
	}
	raw, err := fontFiles.ReadFile("fonts/" + name)
	if err != nil {
		return false
	}
	// Publicly cached assets must never carry a workspace session cookie.
	w.Header().Del("Set-Cookie")
	w.Header().Set("Content-Type", "font/woff2")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	_, _ = w.Write(raw)
	return true
}
