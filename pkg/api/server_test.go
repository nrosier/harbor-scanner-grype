package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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
	return New(Options{
		Scanner:     harbor.Scanner{Name: "Grype", Vendor: "Anchore", Version: "0.112.0"},
		DBUpdatedAt: func() time.Time { return time.Date(2026, 9, 6, 1, 31, 12, 0, time.UTC) },
	}, job.NewMemoryStore(), fr)
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
	s := newServer(t, &fakeRunner{version: "0.112.0"})
	rr := do(s, http.MethodGet, BasePath+"/metadata", nil, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("metadata = %d %s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != harbor.MimeTypeMetadata {
		t.Fatalf("content-type = %q", ct)
	}
	var md harbor.ScannerAdapterMetadata
	if err := json.Unmarshal(rr.Body.Bytes(), &md); err != nil {
		t.Fatal(err)
	}
	if md.Scanner.Name != "Grype" || md.Scanner.Vendor != "Anchore" || md.Scanner.Version != "0.112.0" {
		t.Errorf("scanner = %+v", md.Scanner)
	}
	if len(md.Capabilities) != 1 {
		t.Fatalf("want exactly one capability, got %d", len(md.Capabilities))
	}
	c := md.Capabilities[0]
	wantConsumes := []string{harbor.MimeTypeOCIArtifact, harbor.MimeTypeDockerArtifact}
	wantProduces := []string{harbor.MimeTypeSecurityVulnReport, harbor.MimeTypeLegacyVulnReport}
	if strings.Join(c.ConsumesMimeTypes, ",") != strings.Join(wantConsumes, ",") {
		t.Errorf("consumes = %v", c.ConsumesMimeTypes)
	}
	if strings.Join(c.ProducesMimeTypes, ",") != strings.Join(wantProduces, ",") {
		t.Errorf("produces = %v", c.ProducesMimeTypes)
	}
	if md.Properties[harbor.PropScannerType] != harbor.ScannerTypeOSPackageVuln {
		t.Errorf("scanner-type = %q", md.Properties[harbor.PropScannerType])
	}
	if md.Properties[harbor.PropVulnDBUpdatedAt] != "2026-09-06T01:31:12Z" {
		t.Errorf("db-updated-at = %q", md.Properties[harbor.PropVulnDBUpdatedAt])
	}
	if md.Properties[harbor.PropRegistryAuthorizationType] != "Bearer" {
		t.Errorf("registry-authorization-type = %q, want Bearer", md.Properties[harbor.PropRegistryAuthorizationType])
	}
}

func TestMetadataOmitsDBPropertyWhenUnknown(t *testing.T) {
	s := New(Options{Scanner: harbor.Scanner{Name: "Grype"}}, job.NewMemoryStore(), &fakeRunner{})
	md := s.Metadata()
	if _, ok := md.Properties[harbor.PropVulnDBUpdatedAt]; ok {
		t.Errorf("db property must be omitted when DBUpdatedAt is nil")
	}
	if md.Properties == nil {
		t.Errorf("properties must never be nil")
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
	rr := do(s, http.MethodGet, path, nil, "application/vnd.security.sbom.report+json; version=1.0")
	if rr.Code != http.StatusBadRequest || rr.Header().Get("Content-Type") != harbor.MimeTypeError {
		t.Errorf("unsupported Accept -> %d %q, want 400 error", rr.Code, rr.Header().Get("Content-Type"))
	}
}

func TestReportUnknownAndFailed(t *testing.T) {
	s := newServer(t, &fakeRunner{err: errors.New("grype: registry unauthorized")})
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
	if !strings.Contains(e.Error.Message, "unauthorized") {
		t.Errorf("error message must carry the cause, got %q", e.Error.Message)
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
