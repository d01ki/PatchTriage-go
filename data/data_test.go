package data

import "testing"

func TestEmbeddedFiles(t *testing.T) {
	for _, name := range []string{
		"ssvc_validation.json", "demo_kev.json", "demo_epss.json", "demo_nvd.json",
		"demo_vulnrichment.json", "demo_assets.yaml",
		"fixtures/trivy_sample.json", "fixtures/grype_sample.json",
	} {
		raw, err := ReadFile(name)
		if err != nil || len(raw) == 0 {
			t.Errorf("ReadFile(%q) = %d bytes, %v", name, len(raw), err)
		}
	}
}
