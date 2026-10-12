// Package data embeds the offline demo evidence, demo inventory, bundled
// scanner fixtures and the pinned SSVC validation expectations.
package data

import "embed"

//go:embed *.json *.yaml fixtures/*.json
var FS embed.FS

// ReadFile returns one embedded file, e.g. "demo_kev.json".
func ReadFile(name string) ([]byte, error) { return FS.ReadFile(name) }
