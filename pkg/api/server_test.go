package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TechPrototyper/harbor-scanner-grype/pkg/grype"
	"github.com/TechPrototyper/harbor-scanner-grype/pkg/harbor"
	"github.com/TechPrototyper/harbor-scanner-grype/pkg/job"
)

type fakeRunner struct {
	doc     *grype.Document
	err     error
	release chan struct{} // if non-nil, Scan blocks until closed
	version string
}

func (f *fakeRunner) Scan(ctx context.Context, req harbor.ScanRequest) (*grype.Document, error) {
	if f.release != nil {
		select {
		case <-f.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return f.doc, f.err
}

func (f *fakeRunner) Version(ctx context.Context) (string, time.Time, error) {
	return f.version, time.Time{}, nil
}

type fakeSBOM struct {
	doc     json.RawMessage
	err     error
	release chan struct{} // if non-nil, GenerateSPDX blocks until closed
	panics  bool
}

func (f *fakeSBOM) GenerateSPDX(ctx context.Context, req harbor.ScanRequest) (json.RawMessage, error) {
	if f.release != nil {
		select {
		case <-f.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if f.panics {
		panic("boom")
	}
	return f.doc, f.err
}

const spdxDoc = `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"lib/app","packages":[{"name":"musl"}]}`

func newSBOM() *fakeSBOM { return &fakeSBOM{doc: json.RawMessage(spdxDoc)} }

func fixtureDoc(t *testing.T) *grype.Document {
	t.Helper()
	raw, err := os.ReadFile("../grype/testdata/grype-sample.json")
	if err != nil {
		t.Fatal(err)
	}
	var d grype.Document
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	return &d
}

func newServer(t *testing.T, fr *fakeRunner) *Server {
	t.Helper()
	return newServerSBOM(t, fr, newSBOM())
}

func newServerSBOM(t *testing.T, fr *fakeRunner, fs *fakeSBOM) *Server {
	t.Helper()
	return New(Options{
		Scanner:     harbor.Scanner{Name: "Grype", Vendor: "Anchore", Version: "0.121.2"},
		DBUpdatedAt: func() time.Time { return time.Date(2026, 9, 6, 1, 31, 12, 0, time.UTC) },
	}, job.NewMemoryStore(), fr, fs)
}

func scanBody() []byte {
	b, _ := json.Marshal(harbor.ScanRequest{
		Registry: harbor.Registry{URL: "https://harbor.example", Authorization: "Basic abc"},
		Artifact: harbor.Artifact{Repository: "lib/app", Digest: "sha256:0000", MimeType: harbor.MimeTypeOCIArtifact},
	})
	return b
}

func do(s *Server, method, path string, body []byte, accept string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	return rr
}

func postScan(t *testing.T, s *Server) string {
	t.Helper()
	rr := do(s, http.MethodPost, BasePath+"/scan", scanBody(), "")
	if rr.Code != http.StatusAccepted {
		t.Fatalf("POST /scan = %d %s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != harbor.MimeTypeScanResponse {
		t.Fatalf("content-type = %q", ct)
	}
	var resp harbor.ScanResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil || resp.ID == "" {
		t.Fatalf("bad scan response %q: %v", rr.Body.String(), err)
	}
	return resp.ID
}

func waitFinished(t *testing.T, s *Server, id string) *httptest.ResponseRecorder {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		rr := do(s, http.MethodGet, BasePath+"/scan/"+id+"/report", nil, harbor.MimeTypeSecurityVulnReport)
		if rr.Code != http.StatusFound {
			return rr
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("scan never finished")
	return nil
}

func TestHealthz(t *testing.T) {
	s := newServer(t, &fakeRunner{})
	rr := do(s, http.MethodGet, "/healthz", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("healthz = %d", rr.Code)
	}
}

func TestMetadata(t *testing.T) {
	s := newServer(t, &fakeRunner{version: "0.121.2"})
	rr := do(s, http.MethodGet, BasePath+"/metadata", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("metadata = %d %s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != harbor.MimeTypeMetadata {
		t.Fatalf("content-type = %q", ct)
	}
	want := `{"scanner":{"name":"Grype","vendor":"Anchore","version":"0.121.2"},` +
		`"capabilities":[` +
		`{"type":"vulnerability","consumes_mime_types":["application/vnd.oci.image.manifest.v1+json","application/vnd.docker.distribution.manifest.v2+json"],` +
		`"produces_mime_types":["application/vnd.security.vulnerability.report; version=1.1","application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"]},` +
		`{"type":"sbom","consumes_mime_types":["application/vnd.oci.image.manifest.v1+json","application/vnd.docker.distribution.manifest.v2+json"],` +
		`"produces_mime_types":["application/vnd.security.sbom.report+json; version=1.0"],` +
		`"additional_attributes":{"sbom_media_types":["application/spdx+json"]}}],` +
		`"properties":{"harbor.scanner-adapter/registry-authorization-type":"Bearer",` +
		`"harbor.scanner-adapter/scanner-type":"os-package-vulnerability",` +
		`"harbor.scanner-adapter/vulnerability-database-updated-at":"2026-09-06T01:31:12Z"}}`
	if got := strings.TrimSpace(rr.Body.String()); got != want {
		t.Fatalf("metadata JSON:\n got %s\nwant %s", got, want)
	}
}

func TestMetadataWithoutSBOMKeepsUntypedVulnerabilityCapability(t *testing.T) {
	s := New(Options{
		Scanner:     harbor.Scanner{Name: "Grype", Vendor: "Anchore", Version: "0.121.2"},
		DBUpdatedAt: func() time.Time { return time.Date(2026, 9, 6, 1, 31, 12, 0, time.UTC) },
	}, job.NewMemoryStore(), &fakeRunner{version: "0.121.2"}, nil)
	rr := do(s, http.MethodGet, BasePath+"/metadata", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("metadata = %d %s", rr.Code, rr.Body.String())
	}
	want := `{"scanner":{"name":"Grype","vendor":"Anchore","version":"0.121.2"},` +
		`"capabilities":[` +
		`{"consumes_mime_types":["application/vnd.oci.image.manifest.v1+json","application/vnd.docker.distribution.manifest.v2+json"],` +
		`"produces_mime_types":["application/vnd.security.vulnerability.report; version=1.1","application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"]}],` +
		`"properties":{"harbor.scanner-adapter/registry-authorization-type":"Bearer",` +
		`"harbor.scanner-adapter/scanner-type":"os-package-vulnerability",` +
		`"harbor.scanner-adapter/vulnerability-database-updated-at":"2026-09-06T01:31:12Z"}}`
	if got := strings.TrimSpace(rr.Body.String()); got != want {
		t.Fatalf("metadata JSON:\n got %s\nwant %s", got, want)
	}
}

func TestMetadataOmitsDBPropertyWhenUnknown(t *testing.T) {
	s := New(Options{Scanner: harbor.Scanner{Name: "Grype"}}, job.NewMemoryStore(), &fakeRunner{}, newSBOM())
	md := s.Metadata()
	if _, ok := md.Properties[harbor.PropVulnDBUpdatedAt]; ok {
		t.Errorf("db property must be omitted when DBUpdatedAt is nil")
	}
	if md.Properties == nil {
		t.Errorf("properties must never be nil")
	}
}

func TestMetadataReflectsChangingDBTimestamp(t *testing.T) {
	cur := time.Date(2026, 9, 6, 1, 31, 12, 0, time.UTC)
	s := New(Options{Scanner: harbor.Scanner{Name: "Grype"}, DBUpdatedAt: func() time.Time { return cur }},
		job.NewMemoryStore(), &fakeRunner{}, newSBOM())
	if got := s.Metadata().Properties[harbor.PropVulnDBUpdatedAt]; got != "2026-09-06T01:31:12Z" {
		t.Fatalf("first: %q", got)
	}
	cur = time.Date(2026, 9, 7, 2, 0, 0, 0, time.UTC)
	if got := s.Metadata().Properties[harbor.PropVulnDBUpdatedAt]; got != "2026-09-07T02:00:00Z" {
		t.Fatalf("after change: %q", got)
	}
	cur = time.Time{}
	if _, ok := s.Metadata().Properties[harbor.PropVulnDBUpdatedAt]; ok {
		t.Fatalf("property must be omitted when func returns zero")
	}
}

func TestScanValidation(t *testing.T) {
	s := newServer(t, &fakeRunner{doc: &grype.Document{}})
	rr := do(s, http.MethodPost, BasePath+"/scan", []byte("{not json"), "")
	if rr.Code != http.StatusBadRequest || rr.Header().Get("Content-Type") != harbor.MimeTypeError {
		t.Fatalf("bad json = %d %q", rr.Code, rr.Header().Get("Content-Type"))
	}
	var e harbor.ErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &e); err != nil || e.Error.Message == "" {
		t.Fatalf("error envelope missing: %s", rr.Body.String())
	}

	bad, _ := json.Marshal(harbor.ScanRequest{
		Registry: harbor.Registry{URL: "https://h"},
		Artifact: harbor.Artifact{Repository: "r", Digest: "sha256:1", MimeType: "application/vnd.example.chart"},
	})
	rr = do(s, http.MethodPost, BasePath+"/scan", bad, "")
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("unsupported artifact mime = %d, want 422", rr.Code)
	}

	missing, _ := json.Marshal(harbor.ScanRequest{Registry: harbor.Registry{URL: "https://h"}})
	rr = do(s, http.MethodPost, BasePath+"/scan", missing, "")
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("missing repository/digest = %d, want 422", rr.Code)
	}

	// empty artifact mime type is treated as OCI (Harbor omits it sometimes)
	noMime, _ := json.Marshal(harbor.ScanRequest{
		Registry: harbor.Registry{URL: "https://h"},
		Artifact: harbor.Artifact{Repository: "r", Digest: "sha256:1"},
	})
	rr = do(s, http.MethodPost, BasePath+"/scan", noMime, "")
	if rr.Code != http.StatusAccepted {
		t.Fatalf("empty mime must be accepted, got %d", rr.Code)
	}
}

func TestReportPendingThenFinished(t *testing.T) {
	fr := &fakeRunner{doc: fixtureDoc(t), release: make(chan struct{})}
	s := newServer(t, fr)
	id := postScan(t, s)

	rr := do(s, http.MethodGet, BasePath+"/scan/"+id+"/report", nil, "")
	if rr.Code != http.StatusFound {
		t.Fatalf("pending report = %d, want 302", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != BasePath+"/scan/"+id+"/report" {
		t.Errorf("Location = %q", loc)
	}
	if ra := rr.Header().Get("Refresh-After"); ra != "15" {
		t.Errorf("Refresh-After = %q, want 15", ra)
	}

	close(fr.release)
	rr = waitFinished(t, s, id)
	if rr.Code != http.StatusOK {
		t.Fatalf("finished report = %d %s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != harbor.MimeTypeSecurityVulnReport {
		t.Errorf("content-type = %q", ct)
	}
	var rep harbor.ScanReport
	if err := json.Unmarshal(rr.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Vulnerabilities) != 3 || rep.Severity != harbor.SevCritical {
		t.Errorf("report = %d items, severity %s", len(rep.Vulnerabilities), rep.Severity)
	}
	if rep.Artifact.Repository != "lib/app" || rep.Scanner.Name != "Grype" {
		t.Errorf("envelope = %+v %+v", rep.Artifact, rep.Scanner)
	}
}

func TestReportAcceptNegotiation(t *testing.T) {
	s := newServer(t, &fakeRunner{doc: &grype.Document{}})
	id := postScan(t, s)
	waitFinished(t, s, id)
	path := BasePath + "/scan/" + id + "/report"

	cases := map[string]string{
		"":                                harbor.MimeTypeSecurityVulnReport,
		"*/*":                             harbor.MimeTypeSecurityVulnReport,
		harbor.MimeTypeSecurityVulnReport: harbor.MimeTypeSecurityVulnReport,
		harbor.MimeTypeLegacyVulnReport:   harbor.MimeTypeLegacyVulnReport,
		"text/html, " + harbor.MimeTypeLegacyVulnReport: harbor.MimeTypeLegacyVulnReport,
	}
	for accept, want := range cases {
		rr := do(s, http.MethodGet, path, nil, accept)
		if rr.Code != http.StatusOK || rr.Header().Get("Content-Type") != want {
			t.Errorf("Accept %q -> %d %q, want 200 %q", accept, rr.Code, rr.Header().Get("Content-Type"), want)
		}
	}
	rr := do(s, http.MethodGet, path, nil, "text/html")
	if rr.Code != http.StatusNotImplemented || rr.Header().Get("Content-Type") != harbor.MimeTypeError {
		t.Errorf("unsupported Accept -> %d %q, want 501 error", rr.Code, rr.Header().Get("Content-Type"))
	}
	var e harbor.ErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &e); err != nil || !strings.Contains(e.Error.Message, `unsupported media type: "text/html"`) {
		t.Errorf("501 body = %s", rr.Body.String())
	}
}

func TestReportUnknownAndFailed(t *testing.T) {
	s := newServer(t, &fakeRunner{err: errors.New("run /usr/local/bin/grype: exit status 1: stderr: registry unauthorized")})
	rr := do(s, http.MethodGet, BasePath+"/scan/does-not-exist/report", nil, "")
	if rr.Code != http.StatusNotFound || rr.Header().Get("Content-Type") != harbor.MimeTypeError {
		t.Fatalf("unknown = %d %q", rr.Code, rr.Header().Get("Content-Type"))
	}
	id := postScan(t, s)
	rr = waitFinished(t, s, id)
	if rr.Code != http.StatusInternalServerError || rr.Header().Get("Content-Type") != harbor.MimeTypeError {
		t.Fatalf("failed = %d %q", rr.Code, rr.Header().Get("Content-Type"))
	}
	var e harbor.ErrorResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &e)
	if e.Error.Message != "grype scan failed" {
		t.Errorf("error message must be the sanitized stable message, got %q", e.Error.Message)
	}
	if strings.Contains(e.Error.Message, "/usr/local/bin") || strings.Contains(e.Error.Message, "unauthorized") {
		t.Errorf("error message leaks binary path or stderr: %q", e.Error.Message)
	}
}

func TestMethodNotAllowedAndUnknownRoute(t *testing.T) {
	s := newServer(t, &fakeRunner{})
	if rr := do(s, http.MethodGet, BasePath+"/scan", nil, ""); rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /scan = %d, want 405", rr.Code)
	}
	if rr := do(s, http.MethodGet, BasePath+"/nope", nil, ""); rr.Code != http.StatusNotFound {
		t.Errorf("unknown route = %d, want 404", rr.Code)
	}
}

// ---- SBOM / enabled_capabilities ----

func capsBody(caps ...harbor.EnabledCapability) []byte {
	b, _ := json.Marshal(harbor.ScanRequest{
		Registry:            harbor.Registry{URL: "https://harbor.example", Authorization: "Basic abc"},
		Artifact:            harbor.Artifact{Repository: "lib/app", Digest: "sha256:0000", MimeType: harbor.MimeTypeOCIArtifact},
		EnabledCapabilities: caps,
	})
	return b
}

func vulnCap() harbor.EnabledCapability {
	return harbor.EnabledCapability{Type: "vulnerability", ProducesMimeTypes: []string{harbor.MimeTypeSecurityVulnReport}}
}

func sbomCap(mediaTypes ...string) harbor.EnabledCapability {
	return harbor.EnabledCapability{
		Type:              "sbom",
		ProducesMimeTypes: []string{harbor.MimeTypeSecuritySBOMReport},
		Parameters:        &harbor.CapabilityAttributes{SBOMMediaTypes: mediaTypes},
	}
}

func postCaps(t *testing.T, s *Server, caps ...harbor.EnabledCapability) string {
	t.Helper()
	rr := do(s, http.MethodPost, BasePath+"/scan", capsBody(caps...), "")
	if rr.Code != http.StatusAccepted {
		t.Fatalf("POST /scan = %d %s", rr.Code, rr.Body.String())
	}
	var resp harbor.ScanResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil || resp.ID == "" {
		t.Fatalf("bad scan response %q: %v", rr.Body.String(), err)
	}
	return resp.ID
}

func sbomPath(id string) string {
	return BasePath + "/scan/" + id + "/report?sbom_media_type=" + url.QueryEscape(harbor.MediaTypeSPDX)
}

func getSBOM(s *Server, id string) *httptest.ResponseRecorder {
	return do(s, http.MethodGet, sbomPath(id), nil, harbor.MimeTypeSecuritySBOMReport)
}

func waitSBOM(t *testing.T, s *Server, id string) *httptest.ResponseRecorder {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		rr := getSBOM(s, id)
		if rr.Code != http.StatusFound {
			return rr
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("sbom never finished")
	return nil
}

func TestScanDefaultsToVulnerabilityOnly(t *testing.T) {
	for name, caps := range map[string][]harbor.EnabledCapability{
		"absent":   nil,
		"explicit": {vulnCap()},
		"legacy":   {{Type: "vulnerability", ProducesMimeTypes: []string{harbor.MimeTypeLegacyVulnReport}}},
	} {
		t.Run(name, func(t *testing.T) {
			s := newServer(t, &fakeRunner{doc: fixtureDoc(t)})
			id := postCaps(t, s, caps...)
			rr := waitFinished(t, s, id)
			if rr.Code != http.StatusOK {
				t.Fatalf("vuln report = %d %s", rr.Code, rr.Body.String())
			}
			// no SBOM job exists
			if rr := getSBOM(s, id); rr.Code != http.StatusNotFound {
				t.Errorf("sbom for vuln-only scan = %d, want 404", rr.Code)
			}
		})
	}
}

func TestScanSBOMOnly(t *testing.T) {
	fr := &fakeRunner{err: errors.New("must not run")}
	s := newServerSBOM(t, fr, newSBOM())
	id := postCaps(t, s, sbomCap(harbor.MediaTypeSPDX))
	rr := waitSBOM(t, s, id)
	if rr.Code != http.StatusOK {
		t.Fatalf("sbom report = %d %s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != harbor.MimeTypeSecuritySBOMReport {
		t.Errorf("content-type = %q", ct)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(bytes.TrimSpace(raw["sbom"]), []byte("{")) {
		t.Errorf("sbom must be a JSON object, got %s", raw["sbom"])
	}
	var rep harbor.SBOMReport
	if err := json.Unmarshal(rr.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.MediaType != harbor.MediaTypeSPDX || rep.Scanner.Name != "Grype" || rep.Scanner.Version != "0.121.2" ||
		rep.Artifact.Repository != "lib/app" || rep.Artifact.Digest != "sha256:0000" || rep.GeneratedAt.IsZero() {
		t.Errorf("envelope = %+v", rep)
	}
	var got, want any
	_ = json.Unmarshal(rep.SBOM, &got)
	_ = json.Unmarshal([]byte(spdxDoc), &want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("sbom = %s", rep.SBOM)
	}
	// no vuln job
	if rr := do(s, http.MethodGet, BasePath+"/scan/"+id+"/report", nil, ""); rr.Code != http.StatusNotFound {
		t.Errorf("vuln for sbom-only scan = %d, want 404", rr.Code)
	}
}

func TestScanBothCapabilitiesShareID(t *testing.T) {
	s := newServer(t, &fakeRunner{doc: fixtureDoc(t)})
	// duplicate sbom media type entries are deduplicated
	id := postCaps(t, s, vulnCap(), sbomCap(harbor.MediaTypeSPDX, harbor.MediaTypeSPDX), sbomCap(harbor.MediaTypeSPDX))
	if rr := waitFinished(t, s, id); rr.Code != http.StatusOK {
		t.Fatalf("vuln = %d %s", rr.Code, rr.Body.String())
	}
	if rr := waitSBOM(t, s, id); rr.Code != http.StatusOK {
		t.Fatalf("sbom = %d %s", rr.Code, rr.Body.String())
	}
}

func TestScanCapabilityValidation(t *testing.T) {
	s := newServer(t, &fakeRunner{doc: &grype.Document{}})
	cases := []struct {
		name string
		caps []harbor.EnabledCapability
		code int
		msg  string
	}{
		{"unknown type", []harbor.EnabledCapability{{Type: "malware", ProducesMimeTypes: []string{"x"}}}, 422, "unsupported capability type"},
		{"missing type", []harbor.EnabledCapability{{ProducesMimeTypes: []string{"x"}}}, 422, "unsupported capability type"},
		{"sbom without parameters", []harbor.EnabledCapability{{Type: "sbom", ProducesMimeTypes: []string{harbor.MimeTypeSecuritySBOMReport}}}, 422, "missing SBOM media type"},
		{"sbom empty media types", []harbor.EnabledCapability{sbomCap()}, 422, "missing SBOM media type"},
		{"sbom cyclonedx", []harbor.EnabledCapability{sbomCap("application/vnd.cyclonedx+json")}, 422, `unsupported SBOM media type: "application/vnd.cyclonedx+json"`},
		{"sbom one bad of two", []harbor.EnabledCapability{sbomCap(harbor.MediaTypeSPDX, "application/vnd.cyclonedx+json")}, 422, "unsupported SBOM media type"},
		{"sbom wrong produces", []harbor.EnabledCapability{{Type: "sbom", ProducesMimeTypes: []string{harbor.MimeTypeSecurityVulnReport}, Parameters: &harbor.CapabilityAttributes{SBOMMediaTypes: []string{harbor.MediaTypeSPDX}}}}, 422, "unsupported produces_mime_types"},
		{"vuln wrong produces", []harbor.EnabledCapability{{Type: "vulnerability", ProducesMimeTypes: []string{"text/plain"}}}, 422, "unsupported produces_mime_types"},
		{"vuln empty produces", []harbor.EnabledCapability{{Type: "vulnerability"}}, 400, "produces_mime_types"},
		{"sbom empty produces", []harbor.EnabledCapability{{Type: "sbom", Parameters: &harbor.CapabilityAttributes{SBOMMediaTypes: []string{harbor.MediaTypeSPDX}}}}, 400, "produces_mime_types"},
		{"valid vuln, bad sbom", []harbor.EnabledCapability{vulnCap(), sbomCap("application/vnd.cyclonedx+json")}, 422, "unsupported SBOM media type"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rr := do(s, http.MethodPost, BasePath+"/scan", capsBody(c.caps...), "")
			if rr.Code != c.code || rr.Header().Get("Content-Type") != harbor.MimeTypeError {
				t.Fatalf("= %d %q %s, want %d", rr.Code, rr.Header().Get("Content-Type"), rr.Body.String(), c.code)
			}
			var e harbor.ErrorResponse
			_ = json.Unmarshal(rr.Body.Bytes(), &e)
			if !strings.Contains(e.Error.Message, c.msg) {
				t.Errorf("message = %q, want it to contain %q", e.Error.Message, c.msg)
			}
		})
	}
}

func TestScanSBOMWithoutGeneratorRejected(t *testing.T) {
	s := New(Options{Scanner: harbor.Scanner{Name: "Grype"}}, job.NewMemoryStore(), &fakeRunner{}, nil)
	if rr := do(s, http.MethodPost, BasePath+"/scan", capsBody(sbomCap(harbor.MediaTypeSPDX)), ""); rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("= %d, want 422", rr.Code)
	}
	if n := len(s.Metadata().Capabilities); n != 1 {
		t.Errorf("capabilities = %d, want 1 without generator", n)
	}
}

func TestSBOMReportPendingRunningFinished(t *testing.T) {
	fs := newSBOM()
	fs.release = make(chan struct{})
	s := newServerSBOM(t, &fakeRunner{doc: &grype.Document{}}, fs)
	id := postCaps(t, s, sbomCap(harbor.MediaTypeSPDX))

	// Pending or Running (the goroutine blocks in the generator): both 302.
	for i := 0; i < 2; i++ {
		rr := getSBOM(s, id)
		if rr.Code != http.StatusFound {
			t.Fatalf("in-flight sbom = %d, want 302", rr.Code)
		}
		if loc := rr.Header().Get("Location"); loc != sbomPath(id) {
			t.Errorf("Location = %q, want %q", loc, sbomPath(id))
		}
		if ra := rr.Header().Get("Refresh-After"); ra != "15" {
			t.Errorf("Refresh-After = %q, want 15", ra)
		}
		if i == 0 { // wait until the job is actually Running
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				j, err := s.store.GetJob(job.SBOMKey(id, harbor.MediaTypeSPDX))
				if err == nil && j.Status == job.StatusRunning {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
		}
	}
	close(fs.release)
	if rr := waitSBOM(t, s, id); rr.Code != http.StatusOK {
		t.Fatalf("finished = %d %s", rr.Code, rr.Body.String())
	}
}

func TestSBOMReportFailed(t *testing.T) {
	fs := &fakeSBOM{err: errors.New("run /usr/bin/syft: exit status 1: stderr: registry unauthorized")}
	s := newServerSBOM(t, &fakeRunner{doc: &grype.Document{}}, fs)
	id := postCaps(t, s, sbomCap(harbor.MediaTypeSPDX))
	rr := waitSBOM(t, s, id)
	if rr.Code != http.StatusInternalServerError || rr.Header().Get("Content-Type") != harbor.MimeTypeError {
		t.Fatalf("failed = %d %q", rr.Code, rr.Header().Get("Content-Type"))
	}
	var e harbor.ErrorResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &e)
	if e.Error.Message != "syft sbom generation failed" {
		t.Errorf("message = %q, want sanitized stable message", e.Error.Message)
	}
	if strings.Contains(e.Error.Message, "/usr/bin") || strings.Contains(e.Error.Message, "unauthorized") {
		t.Errorf("message leaks binary path or stderr: %q", e.Error.Message)
	}
}

// A typed grype.Failure surfaces only its Public message.
func TestReportUsesFailurePublicMessage(t *testing.T) {
	ferr := &grype.Failure{Public: "grype scan failed: timed out after 5m0s", Err: errors.New("run /opt/grype: signal: killed: stderr: secret")}
	s := newServer(t, &fakeRunner{err: ferr})
	id := postScan(t, s)
	rr := waitFinished(t, s, id)
	var e harbor.ErrorResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &e)
	if e.Error.Message != "grype scan failed: timed out after 5m0s" {
		t.Errorf("message = %q", e.Error.Message)
	}
}

func TestSBOMReportPanicRecovered(t *testing.T) {
	s := newServerSBOM(t, &fakeRunner{doc: &grype.Document{}}, &fakeSBOM{panics: true})
	id := postCaps(t, s, sbomCap(harbor.MediaTypeSPDX))
	rr := waitSBOM(t, s, id)
	if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), "panicked") {
		t.Fatalf("panic = %d %s", rr.Code, rr.Body.String())
	}
}

func TestSBOMReportQueryValidationAndLookup(t *testing.T) {
	s := newServer(t, &fakeRunner{doc: &grype.Document{}})
	id := postCaps(t, s, sbomCap(harbor.MediaTypeSPDX))
	waitSBOM(t, s, id)
	base := BasePath + "/scan/" + id + "/report"
	acc := harbor.MimeTypeSecuritySBOMReport

	for name, tc := range map[string]struct {
		path, msg string
		code      int
	}{
		"missing":         {base, "missing SBOM media type", 400},
		"empty":           {base + "?sbom_media_type=", "missing SBOM media type", 400},
		"cyclonedx":       {base + "?sbom_media_type=application%2Fvnd.cyclonedx%2Bjson", `unsupported SBOM media type: "application/vnd.cyclonedx+json"`, 400},
		"unknown id":      {BasePath + "/scan/nope/report?sbom_media_type=application%2Fspdx%2Bjson", "not found", 404},
		"validated first": {BasePath + "/scan/nope/report?sbom_media_type=bogus", "unsupported SBOM media type", 400},
	} {
		rr := do(s, http.MethodGet, tc.path, nil, acc)
		var e harbor.ErrorResponse
		_ = json.Unmarshal(rr.Body.Bytes(), &e)
		if rr.Code != tc.code || rr.Header().Get("Content-Type") != harbor.MimeTypeError || !strings.Contains(e.Error.Message, tc.msg) {
			t.Errorf("%s: %d %q %s, want %d %q", name, rr.Code, rr.Header().Get("Content-Type"), rr.Body.String(), tc.code, tc.msg)
		}
	}
	// SBOM job exists but vuln key requested.
	if rr := do(s, http.MethodGet, base, nil, harbor.MimeTypeSecurityVulnReport); rr.Code != http.StatusNotFound {
		t.Errorf("vuln key on sbom-only scan = %d, want 404", rr.Code)
	}
	// Accept is checked before everything else, including unknown ids.
	if rr := do(s, http.MethodGet, BasePath+"/scan/nope/report", nil, "text/html"); rr.Code != http.StatusNotImplemented {
		t.Errorf("unknown accept on unknown id = %d, want 501", rr.Code)
	}
}

func TestLegacyVulnMimeOnVulnJob(t *testing.T) {
	s := newServer(t, &fakeRunner{doc: fixtureDoc(t)})
	id := postCaps(t, s, vulnCap(), sbomCap(harbor.MediaTypeSPDX))
	waitFinished(t, s, id)
	rr := do(s, http.MethodGet, BasePath+"/scan/"+id+"/report", nil, harbor.MimeTypeLegacyVulnReport)
	if rr.Code != http.StatusOK || rr.Header().Get("Content-Type") != harbor.MimeTypeLegacyVulnReport {
		t.Fatalf("legacy = %d %q", rr.Code, rr.Header().Get("Content-Type"))
	}
	var rep harbor.ScanReport
	if err := json.Unmarshal(rr.Body.Bytes(), &rep); err != nil || len(rep.Vulnerabilities) != 3 {
		t.Fatalf("legacy body: %v %s", err, rr.Body.String())
	}
}

func TestFailureIsolation(t *testing.T) {
	t.Run("sbom fails, vuln succeeds", func(t *testing.T) {
		s := newServerSBOM(t, &fakeRunner{doc: fixtureDoc(t)}, &fakeSBOM{err: errors.New("syft exploded")})
		id := postCaps(t, s, vulnCap(), sbomCap(harbor.MediaTypeSPDX))
		if rr := waitFinished(t, s, id); rr.Code != http.StatusOK {
			t.Errorf("vuln = %d %s, want 200", rr.Code, rr.Body.String())
		}
		if rr := waitSBOM(t, s, id); rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), "syft sbom generation failed") {
			t.Errorf("sbom = %d %s, want 500", rr.Code, rr.Body.String())
		}
	})
	t.Run("vuln fails, sbom succeeds", func(t *testing.T) {
		s := newServerSBOM(t, &fakeRunner{err: errors.New("grype exploded")}, newSBOM())
		id := postCaps(t, s, vulnCap(), sbomCap(harbor.MediaTypeSPDX))
		if rr := waitFinished(t, s, id); rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), "grype scan failed") {
			t.Errorf("vuln = %d %s, want 500", rr.Code, rr.Body.String())
		}
		if rr := waitSBOM(t, s, id); rr.Code != http.StatusOK {
			t.Errorf("sbom = %d %s, want 200", rr.Code, rr.Body.String())
		}
	})
}

// --- readiness and fail-fast ---

type countingRunner struct {
	fakeRunner
	scans int
}

func (c *countingRunner) Scan(ctx context.Context, req harbor.ScanRequest) (*grype.Document, error) {
	c.scans++
	return c.fakeRunner.Scan(ctx, req)
}

func TestReadyzFollowsDBAvailability(t *testing.T) {
	var ready atomic.Bool
	s := New(Options{DBReady: ready.Load}, job.NewMemoryStore(), &fakeRunner{}, newSBOM())

	rr := do(s, http.MethodGet, "/readyz", nil, "")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz without DB = %d, want 503", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != harbor.MimeTypeError {
		t.Fatalf("content-type = %q", ct)
	}
	var er harbor.ErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &er); err != nil || er.Error.Message != grype.MsgDBUnavailable {
		t.Fatalf("body %q: %v", rr.Body.String(), err)
	}
	if rr := do(s, http.MethodGet, "/healthz", nil, ""); rr.Code != http.StatusOK {
		t.Fatalf("liveness must stay 200 without a DB, got %d", rr.Code)
	}

	ready.Store(true)
	if rr := do(s, http.MethodGet, "/readyz", nil, ""); rr.Code != http.StatusOK {
		t.Fatalf("readyz with DB = %d, want 200", rr.Code)
	}
}

func TestReadyzWithoutDBCheckIsReady(t *testing.T) {
	s := newServer(t, &fakeRunner{})
	if rr := do(s, http.MethodGet, "/readyz", nil, ""); rr.Code != http.StatusOK {
		t.Fatalf("readyz = %d", rr.Code)
	}
}

func TestReadyzIs503WhileShuttingDown(t *testing.T) {
	s := New(Options{DBReady: func() bool { return true }}, job.NewMemoryStore(), &fakeRunner{}, newSBOM())
	if rr := do(s, http.MethodGet, "/readyz", nil, ""); rr.Code != http.StatusOK {
		t.Fatalf("readyz = %d", rr.Code)
	}
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	rr := do(s, http.MethodGet, "/readyz", nil, "")
	if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "shutting down") {
		t.Fatalf("readyz while closing = %d %s", rr.Code, rr.Body.String())
	}
	if rr := do(s, http.MethodGet, "/healthz", nil, ""); rr.Code != http.StatusOK {
		t.Fatalf("healthz while closing = %d", rr.Code)
	}
}

func TestVulnJobFailsFastWithoutDBButSBOMStillRuns(t *testing.T) {
	runner := &countingRunner{fakeRunner: fakeRunner{doc: fixtureDoc(t)}}
	s := New(Options{DBReady: func() bool { return false }}, job.NewMemoryStore(), runner, newSBOM())

	body, _ := json.Marshal(harbor.ScanRequest{
		Registry: harbor.Registry{URL: "https://harbor.example", Authorization: "Basic abc"},
		Artifact: harbor.Artifact{Repository: "lib/app", Digest: "sha256:0000", MimeType: harbor.MimeTypeOCIArtifact},
		EnabledCapabilities: []harbor.EnabledCapability{
			{Type: harbor.CapabilityTypeVulnerability, ProducesMimeTypes: []string{harbor.MimeTypeSecurityVulnReport}},
			{Type: harbor.CapabilityTypeSBOM, ProducesMimeTypes: []string{harbor.MimeTypeSecuritySBOMReport},
				Parameters: &harbor.CapabilityAttributes{SBOMMediaTypes: []string{harbor.MediaTypeSPDX}}},
		},
	})
	rr := do(s, http.MethodPost, BasePath+"/scan", body, "")
	if rr.Code != http.StatusAccepted {
		t.Fatalf("POST /scan = %d %s", rr.Code, rr.Body.String())
	}
	var resp harbor.ScanResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)

	vuln := waitFinished(t, s, resp.ID)
	if vuln.Code != http.StatusInternalServerError {
		t.Fatalf("vuln report = %d %s, want 500", vuln.Code, vuln.Body.String())
	}
	var er harbor.ErrorResponse
	if err := json.Unmarshal(vuln.Body.Bytes(), &er); err != nil || er.Error.Message != "vulnerability database not available" {
		t.Fatalf("body %q: %v", vuln.Body.String(), err)
	}
	if runner.scans != 0 {
		t.Fatalf("the Grype runner was called %d times; it must not be called without a DB", runner.scans)
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		sb := do(s, http.MethodGet, BasePath+"/scan/"+resp.ID+"/report?sbom_media_type=application%2Fspdx%2Bjson", nil, harbor.MimeTypeSecuritySBOMReport)
		if sb.Code == http.StatusOK {
			break
		}
		if sb.Code != http.StatusFound || time.Now().After(deadline) {
			t.Fatalf("sbom report = %d %s", sb.Code, sb.Body.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestVulnJobRunsOnceDBBecomesAvailable(t *testing.T) {
	var ready atomic.Bool
	runner := &countingRunner{fakeRunner: fakeRunner{doc: fixtureDoc(t)}}
	s := New(Options{DBReady: ready.Load}, job.NewMemoryStore(), runner, newSBOM())
	id := postScan(t, s)
	if rr := waitFinished(t, s, id); rr.Code != http.StatusInternalServerError {
		t.Fatalf("first scan = %d", rr.Code)
	}
	ready.Store(true)
	id = postScan(t, s)
	if rr := waitFinished(t, s, id); rr.Code != http.StatusOK {
		t.Fatalf("second scan = %d %s", rr.Code, rr.Body.String())
	}
}

func TestRunnerDBLoadFailureReachesHarborAsPublicMessage(t *testing.T) {
	err := &grype.Failure{Public: grype.MsgDBUnavailable, Err: errors.New("grype scan: stderr: /home/nonroot/.cache failed to load vulnerability db")}
	s := New(Options{DBReady: func() bool { return true }}, job.NewMemoryStore(), &fakeRunner{err: err}, newSBOM())
	id := postScan(t, s)
	rr := waitFinished(t, s, id)
	if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), grype.MsgDBUnavailable) || strings.Contains(rr.Body.String(), "/home/nonroot") {
		t.Fatalf("report = %d %s", rr.Code, rr.Body.String())
	}
}
