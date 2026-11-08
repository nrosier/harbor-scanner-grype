// Package grype talks to the Grype CLI and translates its JSON output
// into Harbor reports. The types below mirror the subset of
// grype/presenter/models we consume (grype -o json).
package grype

// Document is the top-level object of `grype -o json`.
type Document struct {
	Matches        []Match        `json:"matches"`
	IgnoredMatches []IgnoredMatch `json:"ignoredMatches,omitempty"`
	Source         *Source        `json:"source,omitempty"`
	Distro         Distribution   `json:"distro"`
	Descriptor     Descriptor     `json:"descriptor"`
}

type Match struct {
	Vulnerability          Vulnerability           `json:"vulnerability"`
	RelatedVulnerabilities []VulnerabilityMetadata `json:"relatedVulnerabilities"`
	MatchDetails           []MatchDetails          `json:"matchDetails"`
	Artifact               Package                 `json:"artifact"`
}

type IgnoredMatch struct {
	Match
	AppliedIgnoreRules []any `json:"appliedIgnoreRules"`
}

type MatchDetails struct {
	Type       string      `json:"type"`
	Matcher    string      `json:"matcher"`
	SearchedBy any         `json:"searchedBy"`
	Found      any         `json:"found"`
	Fix        *FixDetails `json:"fix,omitempty"`
}

type FixDetails struct {
	SuggestedVersion string `json:"suggestedVersion"`
}

type Vulnerability struct {
	VulnerabilityMetadata
	Fix        Fix        `json:"fix"`
	Advisories []Advisory `json:"advisories"`
	Risk       float64    `json:"risk"`
}

type VulnerabilityMetadata struct {
	ID          string   `json:"id"`
	DataSource  string   `json:"dataSource"`
	Namespace   string   `json:"namespace,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	URLs        []string `json:"urls"`
	Description string   `json:"description,omitempty"`
	Cvss        []Cvss   `json:"cvss"`
	CWEs        []CWE    `json:"cwes,omitempty"`
}

// CWE is one entry of a vulnerability's "cwes" list. Grype emits the CWE
// identifier under "cwe" (e.g. "CWE-843"), next to the CVE it was assigned
// to, the reporting source and a Primary/Secondary type.
type CWE struct {
	CVE    string `json:"cve,omitempty"`
	CWE    string `json:"cwe"`
	Source string `json:"source,omitempty"`
	Type   string `json:"type,omitempty"`
}

type Cvss struct {
	Source         string      `json:"source,omitempty"`
	Type           string      `json:"type,omitempty"`
	Version        string      `json:"version"`
	Vector         string      `json:"vector"`
	Metrics        CvssMetrics `json:"metrics"`
	VendorMetadata any         `json:"vendorMetadata"`
}

type CvssMetrics struct {
	BaseScore           float64  `json:"baseScore"`
	ExploitabilityScore *float64 `json:"exploitabilityScore,omitempty"`
	ImpactScore         *float64 `json:"impactScore,omitempty"`
}

type Fix struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"`
}

type Advisory struct {
	ID   string `json:"id"`
	Link string `json:"link"`
}

type Package struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Version   string     `json:"version"`
	Type      string     `json:"type"`
	Locations []Location `json:"locations"`
	Language  string     `json:"language"`
	Licenses  []string   `json:"licenses"`
	CPEs      []string   `json:"cpes"`
	PURL      string     `json:"purl"`
	Upstreams []Upstream `json:"upstreams"`
}

type Upstream struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type Location struct {
	Path    string `json:"path"`
	LayerID string `json:"layerID,omitempty"`
}

type Source struct {
	Type   string `json:"type"`
	Target any    `json:"target"`
}

type Distribution struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Descriptor struct {
	Name          string        `json:"name"`
	Version       string        `json:"version"`
	Configuration any           `json:"configuration,omitempty"`
	DB            *DescriptorDB `json:"db,omitempty"`
	Timestamp     string        `json:"timestamp,omitempty"`
}

type DescriptorDB struct {
	Built         string `json:"built,omitempty"`
	SchemaVersion any    `json:"schemaVersion,omitempty"`
	Checksum      string `json:"checksum,omitempty"`
}
