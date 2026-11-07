// Package harbor defines the wire types of the Harbor Pluggable Scanner
// Adapter API v1.0 (goharbor/pluggable-scanner-spec). Nothing in here is
// specific to Grype; it is the contract Harbor speaks to every adapter.
package harbor

import (
	"encoding/json"
	"time"
)

// MIME types Harbor and the adapter exchange.
const (
	// Artifact types Harbor may ask the adapter to scan.
	MimeTypeOCIArtifact    = "application/vnd.oci.image.manifest.v1+json"
	MimeTypeDockerArtifact = "application/vnd.docker.distribution.manifest.v2+json"
	// Report types the adapter can produce. Harbor >= 2.x requests the
	// v1.1 security report; the legacy harbor+json v1.0 is kept for
	// compatibility. Both share the same JSON shape (ScanReport).
	MimeTypeSecurityVulnReport = "application/vnd.security.vulnerability.report; version=1.1"
	MimeTypeLegacyVulnReport   = "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"
	// SBOM report envelope (scanner spec v1.2). Harbor only consumes the
	// SPDX media type inside it.
	MimeTypeSecuritySBOMReport = "application/vnd.security.sbom.report+json; version=1.0"
	// Envelope types.
	MimeTypeMetadata     = "application/vnd.scanner.adapter.metadata+json; version=1.0"
	MimeTypeScanResponse = "application/vnd.scanner.adapter.scan.response+json; version=1.0"
	MimeTypeError        = "application/vnd.scanner.adapter.error; version=1.0"
)

// MediaTypeSPDX is the only SBOM media type this adapter produces.
const MediaTypeSPDX = "application/spdx+json"

// SupportedSBOMMediaTypes lists the SBOM media types the adapter can emit.
var SupportedSBOMMediaTypes = []string{MediaTypeSPDX}

// Capability types (scanner spec v1.2).
const (
	CapabilityTypeVulnerability = "vulnerability"
	CapabilityTypeSBOM          = "sbom"
)

// Severity values as Harbor expects them (src/pkg/scan/vuln/severity.go).
// Harbor itself remaps Negligible to None when it aggregates.
type Severity string

const (
	SevUnknown    Severity = "Unknown"
	SevNegligible Severity = "Negligible"
	SevLow        Severity = "Low"
	SevMedium     Severity = "Medium"
	SevHigh       Severity = "High"
	SevCritical   Severity = "Critical"
)

// Rank orders severities for comparison (higher is worse).
func (s Severity) Rank() int {
	switch s {
	case SevCritical:
		return 5
	case SevHigh:
		return 4
	case SevMedium:
		return 3
	case SevLow:
		return 2
	case SevNegligible:
		return 1
	default:
		return 0
	}
}

// Registry tells the adapter where and how to pull the artifact.
// Authorization is the raw header value Harbor expects the adapter to
// send to the registry, e.g. "Basic <base64>" or "Bearer <token>".
type Registry struct {
	URL           string `json:"url"`
	Authorization string `json:"authorization"`
}

// Artifact identifies the image to scan.
type Artifact struct {
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
	Tag        string `json:"tag,omitempty"`
	MimeType   string `json:"mime_type,omitempty"`
}

// ScanRequest is the body of POST /api/v1/scan.
type ScanRequest struct {
	Registry Registry `json:"registry"`
	Artifact Artifact `json:"artifact"`
	// EnabledCapabilities is set by Harbor >= 2.13 (spec v1.2); nil when
	// absent, which means a plain vulnerability scan.
	EnabledCapabilities []EnabledCapability `json:"enabled_capabilities,omitempty"`
}

// CapabilityAttributes carries SBOM-specific capability details.
type CapabilityAttributes struct {
	SBOMMediaTypes []string `json:"sbom_media_types"`
}

// EnabledCapability is one capability Harbor asks the adapter to run.
type EnabledCapability struct {
	Type              string                `json:"type"`
	ProducesMimeTypes []string              `json:"produces_mime_types"`
	Parameters        *CapabilityAttributes `json:"parameters,omitempty"`
}

// ScanResponse is the body of the 202 answer to POST /api/v1/scan.
type ScanResponse struct {
	ID string `json:"id"`
}

// Scanner describes the adapter/engine in metadata and in every report.
type Scanner struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor"`
	Version string `json:"version"`
}

// Capability advertises which artifact types can be turned into which
// report types.
//
// Type and AdditionalAttributes are optional (spec v1.2) and omitted when
// zero, so a legacy vulnerability capability marshals exactly as before.
type Capability struct {
	Type                 string                `json:"type,omitempty"`
	ConsumesMimeTypes    []string              `json:"consumes_mime_types"`
	ProducesMimeTypes    []string              `json:"produces_mime_types"`
	AdditionalAttributes *CapabilityAttributes `json:"additional_attributes,omitempty"`
}

// ScannerAdapterMetadata is the body of GET /api/v1/metadata.
// Well-known property keys are listed below.
type ScannerAdapterMetadata struct {
	Scanner      Scanner           `json:"scanner"`
	Capabilities []Capability      `json:"capabilities"`
	Properties   map[string]string `json:"properties"`
}

const (
	PropScannerType               = "harbor.scanner-adapter/scanner-type"
	PropVulnDBUpdatedAt           = "harbor.scanner-adapter/vulnerability-database-updated-at"
	PropRegistryAuthorizationType = "harbor.scanner-adapter/registry-authorization-type"

	ScannerTypeOSPackageVuln = "os-package-vulnerability"
)

// Layer points at the image layer a finding was made in.
type Layer struct {
	Digest string `json:"digest,omitempty"`
	DiffID string `json:"diff_id,omitempty"`
}

// CVSSDetails carries the preferred CVSS scores of a finding.
type CVSSDetails struct {
	ScoreV3  *float64 `json:"score_v3,omitempty"`
	ScoreV2  *float64 `json:"score_v2,omitempty"`
	VectorV3 string   `json:"vector_v3,omitempty"`
	VectorV2 string   `json:"vector_v2,omitempty"`
}

// VulnerabilityItem is one finding in a ScanReport.
type VulnerabilityItem struct {
	ID               string         `json:"id"`
	Pkg              string         `json:"package"`
	Version          string         `json:"version"`
	FixVersion       string         `json:"fix_version,omitempty"`
	Severity         Severity       `json:"severity"`
	Description      string         `json:"description"`
	Links            []string       `json:"links"`
	Layer            *Layer         `json:"layer,omitempty"`
	PreferredCVSS    *CVSSDetails   `json:"preferred_cvss,omitempty"`
	CweIDs           []string       `json:"cwe_ids,omitempty"`
	VendorAttributes map[string]any `json:"vendor_attributes,omitempty"`
}

// ScanReport is the body of GET /api/v1/scan/{id}/report for both
// vulnerability report MIME types.
type ScanReport struct {
	GeneratedAt     time.Time           `json:"generated_at"`
	Artifact        Artifact            `json:"artifact"`
	Scanner         Scanner             `json:"scanner"`
	Severity        Severity            `json:"severity"`
	Vulnerabilities []VulnerabilityItem `json:"vulnerabilities"`
}

// SBOMReport is the body of GET /api/v1/scan/{id}/report for
// MimeTypeSecuritySBOMReport. SBOM holds the raw document (e.g. SPDX JSON)
// and is embedded as a JSON object, not an escaped string.
type SBOMReport struct {
	GeneratedAt time.Time       `json:"generated_at"`
	Artifact    Artifact        `json:"artifact"`
	Scanner     Scanner         `json:"scanner"`
	MediaType   string          `json:"media_type"`
	SBOM        json.RawMessage `json:"sbom"`
}

// Error is the body of every non-2xx answer.
type Error struct {
	Message string `json:"message"`
}

// ErrorResponse wraps Error as the spec requires: {"error": {"message": ...}}.
type ErrorResponse struct {
	Error Error `json:"error"`
}
