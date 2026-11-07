package harbor

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Baseline test: always green, so the workspace has a test suite from
// the very first run.
func TestSeverityRankOrder(t *testing.T) {
	order := []Severity{SevUnknown, SevNegligible, SevLow, SevMedium, SevHigh, SevCritical}
	for i := 1; i < len(order); i++ {
		if order[i].Rank() <= order[i-1].Rank() {
			t.Fatalf("%s must rank above %s", order[i], order[i-1])
		}
	}
}

func TestVulnerabilityCapabilityJSONUnchanged(t *testing.T) {
	c := Capability{
		ConsumesMimeTypes: []string{MimeTypeOCIArtifact, MimeTypeDockerArtifact},
		ProducesMimeTypes: []string{MimeTypeSecurityVulnReport, MimeTypeLegacyVulnReport},
	}
	got, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"consumes_mime_types":["application/vnd.oci.image.manifest.v1+json","application/vnd.docker.distribution.manifest.v2+json"],` +
		`"produces_mime_types":["application/vnd.security.vulnerability.report; version=1.1","application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"]}`
	if string(got) != want {
		t.Fatalf("vulnerability capability changed:\n got %s\nwant %s", got, want)
	}
}

func TestSBOMCapabilityJSON(t *testing.T) {
	c := Capability{
		Type:                 CapabilityTypeSBOM,
		ConsumesMimeTypes:    []string{MimeTypeOCIArtifact},
		ProducesMimeTypes:    []string{MimeTypeSecuritySBOMReport},
		AdditionalAttributes: &CapabilityAttributes{SBOMMediaTypes: SupportedSBOMMediaTypes},
	}
	got, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"type":"sbom","consumes_mime_types":["application/vnd.oci.image.manifest.v1+json"],` +
		`"produces_mime_types":["application/vnd.security.sbom.report+json; version=1.0"],` +
		`"additional_attributes":{"sbom_media_types":["application/spdx+json"]}}`
	if string(got) != want {
		t.Fatalf("sbom capability:\n got %s\nwant %s", got, want)
	}
	if len(SupportedSBOMMediaTypes) != 1 || SupportedSBOMMediaTypes[0] != MediaTypeSPDX {
		t.Fatalf("only SPDX may be supported, got %v", SupportedSBOMMediaTypes)
	}
}

func TestScanRequestEnabledCapabilities(t *testing.T) {
	var absent ScanRequest
	if err := json.Unmarshal([]byte(`{"registry":{"url":"u"},"artifact":{"repository":"r"}}`), &absent); err != nil {
		t.Fatal(err)
	}
	if absent.EnabledCapabilities != nil {
		t.Fatalf("absent array must stay nil, got %v", absent.EnabledCapabilities)
	}
	out, _ := json.Marshal(absent)
	if strings.Contains(string(out), "enabled_capabilities") {
		t.Fatalf("nil capabilities must be omitted: %s", out)
	}

	body := `{"enabled_capabilities":[{"type":"sbom","produces_mime_types":["application/vnd.security.sbom.report+json; version=1.0"],` +
		`"parameters":{"sbom_media_types":["application/spdx+json"]}},{"type":"vulnerability","produces_mime_types":["application/vnd.security.vulnerability.report; version=1.1"]}]}`
	var req ScanRequest
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatal(err)
	}
	if len(req.EnabledCapabilities) != 2 {
		t.Fatalf("want 2 capabilities, got %d", len(req.EnabledCapabilities))
	}
	sbom, vuln := req.EnabledCapabilities[0], req.EnabledCapabilities[1]
	if sbom.Type != CapabilityTypeSBOM || sbom.Parameters == nil || sbom.Parameters.SBOMMediaTypes[0] != MediaTypeSPDX ||
		sbom.ProducesMimeTypes[0] != MimeTypeSecuritySBOMReport {
		t.Fatalf("bad sbom capability: %+v", sbom)
	}
	if vuln.Type != CapabilityTypeVulnerability || vuln.Parameters != nil {
		t.Fatalf("bad vulnerability capability: %+v", vuln)
	}
}

func TestSBOMReportJSON(t *testing.T) {
	r := SBOMReport{
		GeneratedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Artifact:    Artifact{Repository: "lib/app", Digest: "sha256:abc"},
		Scanner:     Scanner{Name: "Syft", Vendor: "Anchore", Version: "1"},
		MediaType:   MediaTypeSPDX,
		SBOM:        json.RawMessage(`{"spdxVersion":"SPDX-2.3","packages":[]}`),
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(data, &generic); err != nil {
		t.Fatal(err)
	}
	obj, ok := generic["sbom"].(map[string]any)
	if !ok || obj["spdxVersion"] != "SPDX-2.3" {
		t.Fatalf("sbom must be a JSON object, got %T: %s", generic["sbom"], data)
	}
	if generic["media_type"] != MediaTypeSPDX || generic["generated_at"] != "2026-01-02T03:04:05Z" {
		t.Fatalf("unexpected envelope: %s", data)
	}
	var back SBOMReport
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if !back.GeneratedAt.Equal(r.GeneratedAt) || string(back.SBOM) != string(r.SBOM) || back.Artifact != r.Artifact {
		t.Fatalf("round trip mismatch: %+v", back)
	}
}
