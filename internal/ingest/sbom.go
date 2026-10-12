package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/d01ki/PatchTriage-go/internal/model"
)

// IsSBOM returns "cyclonedx" or "spdx" when the JSON looks like an SBOM.
func IsSBOM(raw []byte) string {
	fields, ok := objectFields(raw)
	if !ok {
		return ""
	}
	_, hasComponents := fields["components"]
	if flexText(fields["bomFormat"]) == "CycloneDX" || (hasComponents && flexText(fields["specVersion"]) != "") {
		return "cyclonedx"
	}
	_, hasID := fields["SPDXID"]
	_, hasPackages := fields["packages"]
	var version string
	_ = json.Unmarshal(fields["spdxVersion"], &version)
	if strings.HasPrefix(version, "SPDX-") || (hasID && hasPackages) {
		return "spdx"
	}
	return ""
}

func loadSBOM(ctx context.Context, raw []byte, path string, asset *model.Asset, c *OSVClient) (LoadResult, error) {
	return LoadResult{}, errors.New("SBOM resolution is not implemented yet")
}
