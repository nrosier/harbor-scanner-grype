package grype

import (
	"sort"
	"strings"
	"time"

	"github.com/TechPrototyper/harbor-scanner-grype/pkg/harbor"
)

// MapperOptions tune the translation from a Grype Document to a Harbor
// ScanReport.
type MapperOptions struct {
	// PreferCVE replaces non-CVE identifiers (e.g. GHSA-...) with the
	// first related CVE so Harbor CVE allowlists apply. The original ID is
	// kept in vendor_attributes["grype_id"]. Default true.
	PreferCVE bool
}

// DefaultMapperOptions returns the recommended options.
func DefaultMapperOptions() MapperOptions { return MapperOptions{PreferCVE: true} }

// Mapper converts Grype output into Harbor reports.
type Mapper struct {
	Options MapperOptions
	Scanner harbor.Scanner // reported in every ScanReport
	Now     func() time.Time
}

// NewMapper builds a Mapper with DefaultMapperOptions and time.Now.
func NewMapper(scanner harbor.Scanner) *Mapper {
	return &Mapper{Options: DefaultMapperOptions(), Scanner: scanner, Now: time.Now}
}

// Vendor attribute keys written by Map.
const (
	AttrPURL      = "purl"
	AttrNamespace = "namespace"
	AttrMatcher   = "matcher"
	AttrGrypeID   = "grype_id"
	AttrFixState  = "fix_state"
)

// Map translates doc into a ScanReport for artifact. Rules (see
// docs/ARCHITECTURE.md, "Mapping"):
//   - one item per (id, package, version); duplicates are merged, links
//     unioned, first layer kept
//   - severity mapped 1:1 (Critical/High/Medium/Low/Negligible/Unknown)
//   - fix_version = first fix.versions entry, empty otherwise
//   - links = dataSource first, then urls, deduplicated, in order
//   - preferred_cvss from the first CVSS 3.x and first CVSS 2.x entry
//   - cwe_ids from cwes
//   - report.Severity = highest item severity, SevUnknown if no items
//   - items sorted by severity (desc), then id (asc), then package
func (m *Mapper) Map(doc *Document, artifact harbor.Artifact) *harbor.ScanReport {
	items := make([]harbor.VulnerabilityItem, 0, len(doc.Matches))
	index := make(map[itemKey]int, len(doc.Matches))
	for _, match := range doc.Matches {
		id := pickID(match, m.Options.PreferCVE)
		key := itemKey{ID: id, Pkg: match.Artifact.Name, Version: match.Artifact.Version}
		if i, ok := index[key]; ok {
			items[i].Links = unionLinks(items[i].Links, matchLinks(match))
			continue
		}
		index[key] = len(items)
		items = append(items, newItem(match, id))
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Severity.Rank() != items[j].Severity.Rank() {
			return items[i].Severity.Rank() > items[j].Severity.Rank()
		}
		if items[i].ID != items[j].ID {
			return items[i].ID < items[j].ID
		}
		return items[i].Pkg < items[j].Pkg
	})
	severity := harbor.SevUnknown
	for _, item := range items {
		if item.Severity.Rank() > severity.Rank() {
			severity = item.Severity
		}
	}
	return &harbor.ScanReport{
		GeneratedAt:     m.Now(),
		Artifact:        artifact,
		Scanner:         m.Scanner,
		Severity:        severity,
		Vulnerabilities: items,
	}
}

// MapSeverity converts a Grype severity string to Harbor's Severity.
// Matching is case-insensitive; anything unknown becomes SevUnknown.
func MapSeverity(s string) harbor.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return harbor.SevCritical
	case "high":
		return harbor.SevHigh
	case "medium":
		return harbor.SevMedium
	case "low":
		return harbor.SevLow
	case "negligible":
		return harbor.SevNegligible
	default:
		return harbor.SevUnknown
	}
}

// itemKey identifies one merged vulnerability item.
type itemKey struct {
	ID      string
	Pkg     string
	Version string
}

// pickID returns the report item's ID: the match's own ID, or — when
// PreferCVE is set and the ID is not a CVE — the first related CVE.
func pickID(match Match, preferCVE bool) string {
	id := match.Vulnerability.ID
	if !preferCVE || strings.HasPrefix(id, "CVE-") {
		return id
	}
	for _, rel := range match.RelatedVulnerabilities {
		if strings.HasPrefix(rel.ID, "CVE-") {
			return rel.ID
		}
	}
	return id
}

func newItem(match Match, id string) harbor.VulnerabilityItem {
	v := match.Vulnerability
	a := match.Artifact
	return harbor.VulnerabilityItem{
		ID:               id,
		Pkg:              a.Name,
		Version:          a.Version,
		FixVersion:       firstFixVersion(v.Fix.Versions),
		Severity:         MapSeverity(v.Severity),
		Description:      v.Description,
		Links:            matchLinks(match),
		Layer:            layerFrom(a.Locations),
		PreferredCVSS:    preferredCVSS(v.Cvss),
		CweIDs:           cweIDs(v.CWEs),
		VendorAttributes: vendorAttributes(v, a, match.MatchDetails, id),
	}
}

func vendorAttributes(v Vulnerability, a Package, details []MatchDetails, id string) map[string]any {
	attrs := map[string]any{}
	if a.PURL != "" {
		attrs[AttrPURL] = a.PURL
	}
	if v.Namespace != "" {
		attrs[AttrNamespace] = v.Namespace
	}
	if len(details) > 0 && details[0].Matcher != "" {
		attrs[AttrMatcher] = details[0].Matcher
	}
	if v.Fix.State != "" {
		attrs[AttrFixState] = v.Fix.State
	}
	if v.ID != "" && v.ID != id {
		attrs[AttrGrypeID] = v.ID
	}
	return attrs
}

// matchLinks collects a match's links in priority order — the
// vulnerability's dataSource, then its urls, then each related
// vulnerability's dataSource and urls — deduplicated.
func matchLinks(match Match) []string {
	links := make([]string, 0)
	add := func(s string) {
		if s == "" {
			return
		}
		for _, l := range links {
			if l == s {
				return
			}
		}
		links = append(links, s)
	}
	v := match.Vulnerability
	add(v.DataSource)
	for _, u := range v.URLs {
		add(u)
	}
	for _, rel := range match.RelatedVulnerabilities {
		add(rel.DataSource)
		for _, u := range rel.URLs {
			add(u)
		}
	}
	return links
}

// unionLinks appends links from src to dst that are not already present.
func unionLinks(dst, src []string) []string {
	for _, l := range src {
		found := false
		for _, d := range dst {
			if d == l {
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, l)
		}
	}
	return dst
}

func layerFrom(locations []Location) *harbor.Layer {
	if len(locations) > 0 && locations[0].LayerID != "" {
		return &harbor.Layer{Digest: locations[0].LayerID}
	}
	return nil
}

// preferredCVSS picks the first CVSS 3.x and first CVSS 2.x score;
// nil when the match carries none.
func preferredCVSS(cvss []Cvss) *harbor.CVSSDetails {
	var d harbor.CVSSDetails
	for _, c := range cvss {
		score := c.Metrics.BaseScore
		switch {
		case strings.HasPrefix(c.Version, "3.") && d.ScoreV3 == nil:
			d.ScoreV3 = &score
			d.VectorV3 = c.Vector
		case strings.HasPrefix(c.Version, "2.") && d.ScoreV2 == nil:
			d.ScoreV2 = &score
			d.VectorV2 = c.Vector
		}
	}
	if d.ScoreV3 == nil && d.ScoreV2 == nil {
		return nil
	}
	return &d
}

// cweIDs returns the distinct, non-empty CWE identifiers in order of first
// appearance. Grype lists the same CWE once per reporting source (Primary
// and Secondary), so duplicates are common.
func cweIDs(cwes []CWE) []string {
	ids := make([]string, 0, len(cwes))
	seen := make(map[string]struct{}, len(cwes))
	for _, c := range cwes {
		if c.CWE == "" {
			continue
		}
		if _, dup := seen[c.CWE]; dup {
			continue
		}
		seen[c.CWE] = struct{}{}
		ids = append(ids, c.CWE)
	}
	return ids
}

func firstFixVersion(versions []string) string {
	if len(versions) > 0 {
		return versions[0]
	}
	return ""
}
