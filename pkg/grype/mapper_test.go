package grype

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/TechPrototyper/harbor-scanner-grype/pkg/harbor"
)

func loadFixture(t *testing.T) *Document {
	t.Helper()
	raw, err := os.ReadFile("testdata/grype-sample.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("fixture must parse: %v", err)
	}
	if len(doc.Matches) != 4 {
		t.Fatalf("fixture sanity: want 4 matches, got %d", len(doc.Matches))
	}
	return &doc
}

var testArtifact = harbor.Artifact{Repository: "lib/app", Digest: "sha256:0000", Tag: "1.0", MimeType: harbor.MimeTypeOCIArtifact}

func newTestMapper() *Mapper {
	m := NewMapper(harbor.Scanner{Name: "Grype", Vendor: "Anchore", Version: "0.121.2"})
	m.Now = func() time.Time { return time.Date(2026, 9, 7, 10, 0, 0, 0, time.UTC) }
	return m
}

func mustMap(t *testing.T, m *Mapper, doc *Document) *harbor.ScanReport {
	t.Helper()
	rep := m.Map(doc, testArtifact)
	if rep == nil {
		t.Fatal("Map returned nil")
	}
	return rep
}

func findItem(t *testing.T, rep *harbor.ScanReport, id string) harbor.VulnerabilityItem {
	t.Helper()
	for _, v := range rep.Vulnerabilities {
		if v.ID == id {
			return v
		}
	}
	t.Fatalf("item %s not in report (have %v)", id, ids(rep))
	return harbor.VulnerabilityItem{}
}

func ids(rep *harbor.ScanReport) []string {
	out := []string{}
	for _, v := range rep.Vulnerabilities {
		out = append(out, v.ID)
	}
	return out
}

func TestMapSeverity(t *testing.T) {
	cases := map[string]harbor.Severity{
		"Critical": harbor.SevCritical, "critical": harbor.SevCritical,
		"High": harbor.SevHigh, "Medium": harbor.SevMedium, "Low": harbor.SevLow,
		"Negligible": harbor.SevNegligible, "Unknown": harbor.SevUnknown,
		"": harbor.SevUnknown, "bogus": harbor.SevUnknown,
	}
	for in, want := range cases {
		if got := MapSeverity(in); got != want {
			t.Errorf("MapSeverity(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestMapEnvelope(t *testing.T) {
	rep := mustMap(t, newTestMapper(), loadFixture(t))
	if rep.Artifact != testArtifact {
		t.Errorf("artifact must be echoed, got %+v", rep.Artifact)
	}
	if rep.Scanner.Name != "Grype" || rep.Scanner.Version != "0.121.2" {
		t.Errorf("scanner info wrong: %+v", rep.Scanner)
	}
	if !rep.GeneratedAt.Equal(time.Date(2026, 9, 7, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("generated_at must come from Now(), got %v", rep.GeneratedAt)
	}
	if rep.Severity != harbor.SevCritical {
		t.Errorf("report severity must be the max (Critical), got %s", rep.Severity)
	}
}

func TestMapDeduplicatesAndCounts(t *testing.T) {
	rep := mustMap(t, newTestMapper(), loadFixture(t))
	if len(rep.Vulnerabilities) != 3 {
		t.Fatalf("want 3 items (duplicate zlib merged), got %d: %v", len(rep.Vulnerabilities), ids(rep))
	}
	z := findItem(t, rep, "CVE-2023-45853")
	// links: dataSource first, then urls, deduplicated across both matches
	wantLinks := []string{
		"https://nvd.nist.gov/vuln/detail/CVE-2023-45853",
		"https://github.com/madler/zlib/pull/843",
	}
	if len(z.Links) != len(wantLinks) {
		t.Fatalf("zlib links = %v, want %v", z.Links, wantLinks)
	}
	for i := range wantLinks {
		if z.Links[i] != wantLinks[i] {
			t.Fatalf("zlib links = %v, want %v", z.Links, wantLinks)
		}
	}
	if z.Layer == nil || z.Layer.Digest != "sha256:aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111" {
		t.Errorf("first match's layer must win, got %+v", z.Layer)
	}
}

func TestMapFieldsCritical(t *testing.T) {
	rep := mustMap(t, newTestMapper(), loadFixture(t))
	z := findItem(t, rep, "CVE-2023-45853")
	if z.Pkg != "zlib" || z.Version != "1.2.13-r1" {
		t.Errorf("package/version wrong: %s %s", z.Pkg, z.Version)
	}
	if z.FixVersion != "1.3.1" {
		t.Errorf("fix_version = %q, want 1.3.1", z.FixVersion)
	}
	if z.Severity != harbor.SevCritical {
		t.Errorf("severity = %s", z.Severity)
	}
	if z.Description == "" {
		t.Errorf("description must be copied")
	}
	if z.PreferredCVSS == nil || z.PreferredCVSS.ScoreV3 == nil || *z.PreferredCVSS.ScoreV3 != 9.8 {
		t.Fatalf("preferred_cvss.score_v3 = %+v, want 9.8", z.PreferredCVSS)
	}
	if z.PreferredCVSS.VectorV3 != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Errorf("vector_v3 = %q", z.PreferredCVSS.VectorV3)
	}
	if z.PreferredCVSS.ScoreV2 == nil || *z.PreferredCVSS.ScoreV2 != 7.5 || z.PreferredCVSS.VectorV2 != "AV:N/AC:L/Au:N/C:P/I:P/A:P" {
		t.Errorf("cvss v2 = %+v", z.PreferredCVSS)
	}
	if len(z.CweIDs) != 1 || z.CweIDs[0] != "CWE-190" {
		t.Errorf("cwe_ids = %v", z.CweIDs)
	}
	if z.VendorAttributes[AttrPURL] != "pkg:apk/alpine/zlib@1.2.13-r1?arch=x86_64&distro=alpine-3.18" {
		t.Errorf("vendor purl = %v", z.VendorAttributes[AttrPURL])
	}
	if z.VendorAttributes[AttrNamespace] != "nvd:cpe" || z.VendorAttributes[AttrMatcher] != "apk-matcher" {
		t.Errorf("vendor attrs = %v", z.VendorAttributes)
	}
	if z.VendorAttributes[AttrFixState] != "fixed" {
		t.Errorf("fix_state = %v", z.VendorAttributes[AttrFixState])
	}
}

func TestMapPrefersCVEOverGHSA(t *testing.T) {
	rep := mustMap(t, newTestMapper(), loadFixture(t))
	g := findItem(t, rep, "CVE-2024-24790")
	if g.Pkg != "stdlib" || g.Version != "go1.21.5" {
		t.Errorf("package wrong: %+v", g)
	}
	if g.VendorAttributes[AttrGrypeID] != "GHSA-8jgm-h7xq-8rr6" {
		t.Errorf("original GHSA id must be kept in vendor_attributes, got %v", g.VendorAttributes)
	}
	// severity stays the one Grype assigned to the match, not the related CVE's
	if g.Severity != harbor.SevHigh {
		t.Errorf("severity = %s, want High", g.Severity)
	}
	if g.FixVersion != "" {
		t.Errorf("not-fixed must give empty fix_version, got %q", g.FixVersion)
	}
	// links carry both the GHSA and the CVE sources
	has := func(s string) bool {
		for _, l := range g.Links {
			if l == s {
				return true
			}
		}
		return false
	}
	if !has("https://github.com/advisories/GHSA-8jgm-h7xq-8rr6") || !has("https://nvd.nist.gov/vuln/detail/CVE-2024-24790") {
		t.Errorf("links = %v", g.Links)
	}
	if g.PreferredCVSS != nil {
		t.Errorf("no CVSS on the match itself: preferred_cvss must be nil, got %+v", g.PreferredCVSS)
	}
}

func TestMapPreferCVEDisabled(t *testing.T) {
	m := newTestMapper()
	m.Options.PreferCVE = false
	rep := mustMap(t, m, loadFixture(t))
	g := findItem(t, rep, "GHSA-8jgm-h7xq-8rr6")
	if _, ok := g.VendorAttributes[AttrGrypeID]; ok {
		t.Errorf("grype_id must not be set when the id is unchanged")
	}
}

func TestMapNegligibleAndEmpty(t *testing.T) {
	rep := mustMap(t, newTestMapper(), loadFixture(t))
	n := findItem(t, rep, "CVE-2022-1234")
	if n.Severity != harbor.SevNegligible {
		t.Errorf("severity = %s, want Negligible", n.Severity)
	}
	if n.Links == nil || len(n.Links) != 1 || n.Links[0] != "https://security-tracker.debian.org/tracker/CVE-2022-1234" {
		t.Errorf("links must be non-nil and contain dataSource, got %v", n.Links)
	}
	if n.PreferredCVSS != nil || len(n.CweIDs) != 0 {
		t.Errorf("no cvss/cwe expected: %+v %v", n.PreferredCVSS, n.CweIDs)
	}
}

func TestMapOrdering(t *testing.T) {
	rep := mustMap(t, newTestMapper(), loadFixture(t))
	want := []string{"CVE-2023-45853", "CVE-2024-24790", "CVE-2022-1234"}
	got := ids(rep)
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v (severity desc, id asc)", got, want)
		}
	}
}

func TestMapEmptyDocument(t *testing.T) {
	rep := newTestMapper().Map(&Document{}, testArtifact)
	if rep == nil || rep.Vulnerabilities == nil || len(rep.Vulnerabilities) != 0 {
		t.Fatalf("empty doc must give empty non-nil slice, got %+v", rep)
	}
	if rep.Severity != harbor.SevUnknown {
		t.Errorf("empty report severity = %s, want Unknown", rep.Severity)
	}
	raw, _ := json.Marshal(rep)
	if string(raw) == "" || !json.Valid(raw) {
		t.Fatal("report must marshal")
	}
}

// Regression (review after WP2): the first CVSS 3.x and the first CVSS
// 2.x entry must win, and a v2-only entry must never land in the v3 slot.
func TestPreferredCVSSFirstOfEachVersion(t *testing.T) {
	doc := &Document{Matches: []Match{{
		Vulnerability: Vulnerability{VulnerabilityMetadata: VulnerabilityMetadata{
			ID: "CVE-2020-0001", Severity: "High",
			Cvss: []Cvss{
				{Version: "2.0", Vector: "v2-first", Metrics: CvssMetrics{BaseScore: 5.0}},
				{Version: "3.1", Vector: "v3-first", Metrics: CvssMetrics{BaseScore: 8.1}},
				{Version: "3.0", Vector: "v3-second", Metrics: CvssMetrics{BaseScore: 9.9}},
				{Version: "2.0", Vector: "v2-second", Metrics: CvssMetrics{BaseScore: 6.0}},
			},
		}},
		Artifact: Package{Name: "p", Version: "1"},
	}, {
		Vulnerability: Vulnerability{VulnerabilityMetadata: VulnerabilityMetadata{
			ID: "CVE-2020-0002", Severity: "Low",
			Cvss: []Cvss{{Version: "2.0", Vector: "only-v2", Metrics: CvssMetrics{BaseScore: 4.4}}},
		}},
		Artifact: Package{Name: "q", Version: "1"},
	}}}
	rep := mustMap(t, newTestMapper(), doc)
	a := findItem(t, rep, "CVE-2020-0001")
	if a.PreferredCVSS == nil || a.PreferredCVSS.VectorV3 != "v3-first" || *a.PreferredCVSS.ScoreV3 != 8.1 {
		t.Errorf("first v3 must win: %+v", a.PreferredCVSS)
	}
	if a.PreferredCVSS.VectorV2 != "v2-first" || *a.PreferredCVSS.ScoreV2 != 5.0 {
		t.Errorf("first v2 must win: %+v", a.PreferredCVSS)
	}
	b := findItem(t, rep, "CVE-2020-0002")
	if b.PreferredCVSS == nil || b.PreferredCVSS.ScoreV3 != nil || b.PreferredCVSS.VectorV2 != "only-v2" {
		t.Errorf("v2-only entry must fill the v2 slot only: %+v", b.PreferredCVSS)
	}
}

// Regression: Grype emits CWEs as {"cve","cwe","source","type"} and lists the
// same CWE once per source. The mapper used to read a non-existent "id" key,
// which produced cwe_ids [""] for every real scan.
func TestCweIDsDeduplicatedAndNonEmpty(t *testing.T) {
	got := cweIDs([]CWE{
		{CVE: "CVE-2024-6119", CWE: "CWE-843", Source: "openssl-security@openssl.org", Type: "Secondary"},
		{CVE: "CVE-2024-6119", CWE: "CWE-843", Source: "nvd@nist.gov", Type: "Primary"},
		{CWE: ""},
		{CWE: "CWE-20"},
	})
	if len(got) != 2 || got[0] != "CWE-843" || got[1] != "CWE-20" {
		t.Errorf("cweIDs = %q, want [CWE-843 CWE-20]", got)
	}
	if got := cweIDs(nil); got == nil || len(got) != 0 {
		t.Errorf("cweIDs(nil) must be empty non-nil, got %#v", got)
	}
}

// The fixture is a trimmed, unmodified-shape scan of alpine:3.18.4 produced
// by Grype 0.121.2 (DB schema v6.1.10). It guards the mapper against the real
// output schema, not just the hand-written sample.
func TestMapRealGrype0121Output(t *testing.T) {
	raw, err := os.ReadFile("testdata/grype-real-0.121.2.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("real fixture must parse: %v", err)
	}
	if doc.Descriptor.Version != "0.121.2" || len(doc.Matches) != 3 {
		t.Fatalf("fixture sanity: version %q, %d matches", doc.Descriptor.Version, len(doc.Matches))
	}
	rep := mustMap(t, newTestMapper(), &doc)
	if len(rep.Vulnerabilities) != 3 || rep.Severity != harbor.SevCritical {
		t.Fatalf("want 3 items and Critical, got %v / %s", ids(rep), rep.Severity)
	}
	crit := findItem(t, rep, "CVE-2024-5535")
	if crit.Pkg != "libssl3" || crit.Severity != harbor.SevCritical || crit.FixVersion == "" {
		t.Errorf("critical item wrong: %+v", crit)
	}
	if len(crit.CweIDs) != 1 || crit.CweIDs[0] == "" {
		t.Errorf("real output must yield non-empty cwe ids, got %q", crit.CweIDs)
	}
	if crit.PreferredCVSS == nil {
		t.Errorf("real output must yield a preferred CVSS")
	}
	for _, it := range rep.Vulnerabilities {
		for _, c := range it.CweIDs {
			if c == "" {
				t.Errorf("%s has an empty cwe id", it.ID)
			}
		}
	}
	if db := doc.Descriptor.DB; db == nil {
		t.Log("descriptor.db missing in real output")
	}
}
