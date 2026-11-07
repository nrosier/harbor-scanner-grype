// Package api implements the HTTP surface of the Harbor Pluggable
// Scanner Adapter API (spec v1.2: vulnerability and SPDX SBOM reports) on
// top of job.Store, grype.Runner and grype.SBOMGenerator.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TechPrototyper/harbor-scanner-grype/pkg/grype"
	"github.com/TechPrototyper/harbor-scanner-grype/pkg/harbor"
	"github.com/TechPrototyper/harbor-scanner-grype/pkg/job"
)

// BasePath is the prefix Harbor calls.
const BasePath = "/api/v1"

// maxBodyBytes bounds POST /scan request bodies (1 MiB).
const maxBodyBytes = 1 << 20

// Options for the server.
type Options struct {
	Scanner       harbor.Scanner   // name/vendor/version reported in metadata and reports
	RefreshAfter  int              // seconds for the Refresh-After header on 302 (default 15)
	DBUpdatedAt   func() time.Time // for the metadata property; nil -> property omitted
	MapperOptions grype.MapperOptions
	Logger        *slog.Logger // nil -> slog.Default()
	// WorkerConcurrency bounds how many jobs (each one Grype or Syft
	// subprocess) execute at once; further jobs stay Pending. <= 0 -> 2.
	WorkerConcurrency int
}

// defaultWorkerConcurrency matches the config default.
const defaultWorkerConcurrency = 2

// shutdownGrace is how long Shutdown waits for cancelled scans to unwind.
const shutdownGrace = 5 * time.Second

// msgInterrupted is the error stored on jobs cut short by Shutdown.
const msgInterrupted = "interrupted by shutdown"

// Server wires handlers, store, runner and SBOM generator. Scans run in
// goroutines: POST /scan creates one Pending job per requested capability
// (all sharing one scan ID), starts them, and returns 202.
type Server struct {
	opts   Options
	store  job.Store
	runner grype.Runner
	sbom   grype.SBOMGenerator // nil -> SBOM capability neither advertised nor accepted
	now    func() time.Time    // clock for report generated_at; tests may override
	mux    *http.ServeMux

	baseCtx context.Context // parent of every job's scan context; cancelled by Shutdown
	cancel  context.CancelFunc
	sem     chan struct{} // worker slots; acquired inside the job goroutine
	grace   time.Duration // Shutdown's post-cancel unwind budget

	wg      sync.WaitGroup // queued + running job goroutines (and in-progress POSTs)
	mu      sync.Mutex     // guards closing, active; wg.Add happens under it
	closing bool
	active  map[job.Key]struct{} // jobs whose goroutine has not finished
}

// New builds a Server. Routes (all under BasePath):
//
//	GET  /metadata          -> 200 MimeTypeMetadata
//	POST /scan              -> 202 MimeTypeScanResponse | 400 bad json / empty produces_mime_types
//	                           | 422 unsupported artifact mime or capability
//	GET  /scan/{id}/report  -> 302 (+Location, Refresh-After) while Pending/Running
//	                           200 report (Content-Type = negotiated) when Finished
//	                           500 MimeTypeError when Failed
//	                           404 MimeTypeError when unknown (or no job of the negotiated kind)
//	                           400 MimeTypeError when sbom_media_type is missing/unsupported
//	                           501 MimeTypeError when Accept is unsupported
//
// and GET /healthz -> 200 "ok" (outside BasePath). Accept negotiation:
// "", "*/*" and MimeTypeSecurityVulnReport -> MimeTypeSecurityVulnReport;
// MimeTypeLegacyVulnReport -> MimeTypeLegacyVulnReport;
// MimeTypeSecuritySBOMReport -> SBOM report (needs ?sbom_media_type=);
// anything else -> 501. Multiple comma-separated Accept values: first
// supported one wins.
//
// sbom may be nil; then the SBOM capability is not advertised and SBOM
// scan requests are rejected with 422.
func New(opts Options, store job.Store, runner grype.Runner, sbom grype.SBOMGenerator) *Server {
	if opts.RefreshAfter <= 0 {
		opts.RefreshAfter = 15
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.WorkerConcurrency <= 0 {
		opts.WorkerConcurrency = defaultWorkerConcurrency
	}
	baseCtx, cancel := context.WithCancel(context.Background())
	s := &Server{opts: opts, store: store, runner: runner, sbom: sbom, now: time.Now, mux: http.NewServeMux(),
		baseCtx: baseCtx, cancel: cancel, sem: make(chan struct{}, opts.WorkerConcurrency),
		grace: shutdownGrace, active: make(map[job.Key]struct{})}
	s.mux.HandleFunc("GET "+BasePath+"/metadata", s.handleMetadata)
	s.mux.HandleFunc("POST "+BasePath+"/scan", s.handleScan)
	s.mux.HandleFunc("GET "+BasePath+"/scan/{id}/report", s.handleReport)
	s.mux.HandleFunc("/healthz", s.handleHealthz)
	return s
}

// ServeHTTP makes Server an http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// consumedArtifactMimeTypes are the artifact types every capability accepts.
var consumedArtifactMimeTypes = []string{harbor.MimeTypeOCIArtifact, harbor.MimeTypeDockerArtifact}

// vulnReportMimeTypes are the vulnerability report types the adapter produces.
var vulnReportMimeTypes = []string{harbor.MimeTypeSecurityVulnReport, harbor.MimeTypeLegacyVulnReport}

// Metadata assembles the /metadata document. The SBOM capability (spec
// v1.2) is typed and lists the supported SBOM media types. Without SBOM the
// vulnerability capability carries no type (legacy shape, unchanged). With
// SBOM it is typed too: Harbor >= 2.12 treats the scanner as a legacy
// vulnerability-only one only while no capability has a type, so an untyped
// vulnerability capability next to a typed SBOM one would hide vulnerability
// scanning in the UI.
func (s *Server) Metadata() harbor.ScannerAdapterMetadata {
	props := map[string]string{
		harbor.PropScannerType:               harbor.ScannerTypeOSPackageVuln,
		harbor.PropRegistryAuthorizationType: "Bearer",
	}
	if s.opts.DBUpdatedAt != nil {
		if t := s.opts.DBUpdatedAt(); !t.IsZero() {
			props[harbor.PropVulnDBUpdatedAt] = t.UTC().Format(time.RFC3339)
		}
	}
	caps := []harbor.Capability{{
		ConsumesMimeTypes: append([]string(nil), consumedArtifactMimeTypes...),
		ProducesMimeTypes: append([]string(nil), vulnReportMimeTypes...),
	}}
	if s.sbom != nil {
		caps[0].Type = harbor.CapabilityTypeVulnerability
		caps = append(caps, harbor.Capability{
			Type:              harbor.CapabilityTypeSBOM,
			ConsumesMimeTypes: append([]string(nil), consumedArtifactMimeTypes...),
			ProducesMimeTypes: []string{harbor.MimeTypeSecuritySBOMReport},
			AdditionalAttributes: &harbor.CapabilityAttributes{
				SBOMMediaTypes: append([]string(nil), harbor.SupportedSBOMMediaTypes...),
			},
		})
	}
	return harbor.ScannerAdapterMetadata{
		Scanner:      s.opts.Scanner,
		Capabilities: caps,
		Properties:   props,
	}
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, "ok")
}

func (s *Server) handleMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, harbor.MimeTypeMetadata, s.Metadata())
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "read scan request: "+err.Error())
		return
	}
	if len(data) > maxBodyBytes {
		s.writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("scan request body exceeds %d bytes", maxBodyBytes))
		return
	}
	var req harbor.ScanRequest
	if err := json.Unmarshal(data, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "scan request: "+err.Error())
		return
	}
	mime := req.Artifact.MimeType
	if mime == "" {
		mime = harbor.MimeTypeOCIArtifact // Harbor sometimes omits it
	}
	if mime != harbor.MimeTypeOCIArtifact && mime != harbor.MimeTypeDockerArtifact {
		s.writeError(w, http.StatusUnprocessableEntity, fmt.Sprintf("unsupported artifact mime type %q", req.Artifact.MimeType))
		return
	}
	if req.Artifact.Repository == "" || req.Artifact.Digest == "" {
		s.writeError(w, http.StatusUnprocessableEntity, "scan request: artifact repository and digest are required")
		return
	}
	keys, code, msg := s.jobKeys(req.EnabledCapabilities)
	if code != 0 {
		s.writeError(w, code, msg)
		return
	}
	// The closing check and wg.Add share one critical section so Add can
	// never race Shutdown's Wait; the slots are reserved before CreateSet
	// so a rejected request leaves no orphan jobs behind.
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		s.writeError(w, http.StatusServiceUnavailable, "scanner is shutting down")
		return
	}
	s.wg.Add(len(keys))
	s.mu.Unlock()
	jobs, err := s.store.CreateSet(req, keys)
	if err != nil {
		s.wg.Add(-len(keys))
		s.writeError(w, http.StatusInternalServerError, "create job: "+err.Error())
		return
	}
	s.mu.Lock()
	for _, j := range jobs {
		s.active[j.Key()] = struct{}{}
	}
	s.mu.Unlock()
	for _, j := range jobs {
		go s.execute(j)
	}
	writeJSON(w, http.StatusAccepted, harbor.MimeTypeScanResponse, harbor.ScanResponse{ID: jobs[0].ID})
}

// jobKeys validates enabled_capabilities and returns the job keys to create
// (IDs left empty; the store assigns one shared ID). nil/empty means a plain
// vulnerability scan. On a validation failure it returns a non-zero HTTP
// status and message.
func (s *Server) jobKeys(caps []harbor.EnabledCapability) ([]job.Key, int, string) {
	if len(caps) == 0 {
		return []job.Key{{Kind: job.KindVulnerability}}, 0, ""
	}
	vuln := false
	var sbomTypes []string
	for _, c := range caps {
		if c.Type != harbor.CapabilityTypeVulnerability && c.Type != harbor.CapabilityTypeSBOM {
			return nil, http.StatusUnprocessableEntity, fmt.Sprintf("unsupported capability type: %q", c.Type)
		}
		if len(c.ProducesMimeTypes) == 0 {
			return nil, http.StatusBadRequest, fmt.Sprintf("capability %q: produces_mime_types is required", c.Type)
		}
		if c.Type == harbor.CapabilityTypeVulnerability {
			for _, m := range c.ProducesMimeTypes {
				if !slices.Contains(vulnReportMimeTypes, m) {
					return nil, http.StatusUnprocessableEntity, fmt.Sprintf("unsupported produces_mime_types: %q", m)
				}
			}
			vuln = true
			continue
		}
		if s.sbom == nil {
			return nil, http.StatusUnprocessableEntity, "unsupported capability type: \"sbom\" (SBOM generation not configured)"
		}
		if !slices.Contains(c.ProducesMimeTypes, harbor.MimeTypeSecuritySBOMReport) {
			return nil, http.StatusUnprocessableEntity, fmt.Sprintf("unsupported produces_mime_types: %q", strings.Join(c.ProducesMimeTypes, ", "))
		}
		if c.Parameters == nil || len(c.Parameters.SBOMMediaTypes) == 0 {
			return nil, http.StatusUnprocessableEntity, "missing SBOM media type"
		}
		for _, mt := range c.Parameters.SBOMMediaTypes {
			if !slices.Contains(harbor.SupportedSBOMMediaTypes, mt) {
				return nil, http.StatusUnprocessableEntity, fmt.Sprintf("unsupported SBOM media type: %q", mt)
			}
			if !slices.Contains(sbomTypes, mt) {
				sbomTypes = append(sbomTypes, mt)
			}
		}
	}
	var keys []job.Key
	if vuln {
		keys = append(keys, job.Key{Kind: job.KindVulnerability})
	}
	for _, mt := range sbomTypes {
		keys = append(keys, job.Key{Kind: job.KindSBOM, SBOMMediaType: mt})
	}
	return keys, 0, ""
}

// execute is the goroutine body of one job: it waits for a worker slot
// (the job stays Pending meanwhile), runs the job, and always releases the
// slot. If the server shuts down while waiting, the scan is never started.
func (s *Server) execute(j *job.Job) {
	k := j.Key()
	defer s.wg.Done()
	defer func() {
		s.mu.Lock()
		delete(s.active, k)
		s.mu.Unlock()
	}()
	select {
	case s.sem <- struct{}{}:
	case <-s.baseCtx.Done():
		_ = s.store.SetJobError(k, msgInterrupted)
		return
	}
	defer func() { <-s.sem }()
	if s.baseCtx.Err() != nil { // both ready: do not start a scan during shutdown
		_ = s.store.SetJobError(k, msgInterrupted)
		return
	}
	switch j.Kind {
	case job.KindVulnerability:
		s.runVulnJob(j)
	case job.KindSBOM:
		s.runSBOMJob(j)
	}
}

// failMsg is the stored error for a failed scan; a failure caused by
// shutdown cancelling the scan context is reported as an interruption.
func (s *Server) failMsg(err error, fallback string) string {
	if s.baseCtx.Err() != nil {
		return msgInterrupted
	}
	// The full error (binary paths, stderr) is logged by the caller; only a
	// bounded, sanitized message is stored and returned to Harbor.
	return grype.PublicMessage(err, fallback)
}

// Shutdown stops accepting scans (POST /scan answers 503), waits for queued
// and running jobs until ctx expires, then cancels the scan contexts, gives
// them a short grace period to unwind, and marks every job still
// Pending/Running Failed with "interrupted by shutdown". It returns
// ctx.Err() if the wait timed out, nil otherwise.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.closing = true
	s.mu.Unlock()

	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()

	var err error
	select {
	case <-done:
	case <-ctx.Done():
		err = ctx.Err()
		s.cancel()
		t := time.NewTimer(s.grace)
		select {
		case <-done:
		case <-t.C:
		}
		t.Stop()
	}
	s.cancel()

	s.mu.Lock()
	left := make([]job.Key, 0, len(s.active))
	for k := range s.active {
		left = append(left, k)
	}
	s.mu.Unlock()
	for _, k := range left {
		if j, gerr := s.store.GetJob(k); gerr == nil && (j.Status == job.StatusPending || j.Status == job.StatusRunning) {
			_ = s.store.SetJobError(k, msgInterrupted)
		}
	}
	return err
}

// runVulnJob drives one vulnerability job to Finished or Failed via Grype.
// It runs in its own goroutine; panics are recovered and stored as job errors.
func (s *Server) runVulnJob(j *job.Job) {
	k := j.Key()
	defer func() {
		if p := recover(); p != nil {
			_ = s.store.SetJobError(k, fmt.Sprintf("scan panicked: %v", p))
		}
	}()
	if err := s.store.SetJobRunning(k); err != nil {
		return // the job was cleaned up before the scan started
	}
	log := s.jobLogger(j)
	log.Info("scan started")
	start := time.Now()
	doc, err := s.runner.Scan(s.baseCtx, j.Request)
	if err != nil {
		log.Error("scan failed", "error", err.Error(), "duration", time.Since(start).String())
		_ = s.store.SetJobError(k, s.failMsg(err, "grype scan failed"))
		return
	}
	mapper := &grype.Mapper{Options: s.opts.MapperOptions, Scanner: s.opts.Scanner, Now: s.now}
	report := mapper.Map(doc, j.Request.Artifact)
	_ = s.store.SetJobReport(k, report)
	log.Info("scan finished", "severity", string(report.Severity), "findings", len(report.Vulnerabilities),
		"matches", len(doc.Matches), "duration", time.Since(start).String())
}

// runSBOMJob drives one SBOM job to Finished or Failed via the SBOM
// generator. It runs in its own goroutine; panics are recovered and stored
// as job errors. The envelope mirrors the vulnerability report's
// artifact/scanner fields.
func (s *Server) runSBOMJob(j *job.Job) {
	k := j.Key()
	defer func() {
		if p := recover(); p != nil {
			_ = s.store.SetJobError(k, fmt.Sprintf("sbom generation panicked: %v", p))
		}
	}()
	if err := s.store.SetJobRunning(k); err != nil {
		return // the job was cleaned up before generation started
	}
	log := s.jobLogger(j).With("sbom_media_type", j.SBOMMediaType)
	log.Info("sbom started")
	start := time.Now()
	raw, err := s.sbom.GenerateSPDX(s.baseCtx, j.Request)
	if err != nil {
		log.Error("sbom failed", "error", err.Error(), "duration", time.Since(start).String())
		_ = s.store.SetJobError(k, s.failMsg(err, "syft sbom generation failed"))
		return
	}
	report := &harbor.SBOMReport{
		GeneratedAt: s.now(),
		Artifact:    j.Request.Artifact,
		Scanner:     s.opts.Scanner,
		MediaType:   harbor.MediaTypeSPDX,
		SBOM:        raw,
	}
	_ = s.store.SetJobSBOM(k, report)
	log.Info("sbom finished", "bytes", len(raw), "duration", time.Since(start).String())
}

func (s *Server) jobLogger(j *job.Job) *slog.Logger {
	return s.opts.Logger.With("job", j.ID, "kind", string(j.Kind),
		"repository", j.Request.Artifact.Repository, "digest", j.Request.Artifact.Digest)
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	accept := r.Header.Get("Accept")
	mime, ok := negotiateReportMime(accept)
	if !ok {
		s.writeError(w, http.StatusNotImplemented, fmt.Sprintf("unsupported media type: %q", accept))
		return
	}
	id := r.PathValue("id")
	key := job.VulnKey(id)
	location := r.URL.Path
	if mime == harbor.MimeTypeSecuritySBOMReport {
		mediaType := r.URL.Query().Get("sbom_media_type")
		if mediaType == "" {
			s.writeError(w, http.StatusBadRequest, "missing SBOM media type")
			return
		}
		if !slices.Contains(harbor.SupportedSBOMMediaTypes, mediaType) {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported SBOM media type: %q", mediaType))
			return
		}
		key = job.SBOMKey(id, mediaType)
		location = r.URL.RequestURI()
	}
	j, err := s.store.GetJob(key)
	if err != nil {
		if errors.Is(err, job.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, "scan job not found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "read job: "+err.Error())
		return
	}
	switch j.Status {
	case job.StatusPending, job.StatusRunning:
		w.Header().Set("Location", location)
		w.Header().Set("Refresh-After", strconv.Itoa(s.opts.RefreshAfter))
		w.WriteHeader(http.StatusFound)
		return
	case job.StatusFailed:
		msg := j.Error
		if msg == "" {
			msg = "scan failed"
		}
		s.writeError(w, http.StatusInternalServerError, msg)
		return
	}
	if j.Kind == job.KindSBOM {
		writeJSON(w, http.StatusOK, mime, j.SBOMReport)
		return
	}
	writeJSON(w, http.StatusOK, mime, j.Report)
}

// negotiateReportMime picks the report MIME type for an Accept header:
// "" and "*/*" default to the v1.1 security report; among several
// comma-separated values the first supported one wins. The SBOM report
// type is only chosen when named explicitly.
func negotiateReportMime(accept string) (string, bool) {
	if accept == "" || accept == "*/*" {
		return harbor.MimeTypeSecurityVulnReport, true
	}
	for _, part := range strings.Split(accept, ",") {
		part = strings.TrimSpace(part)
		switch part { // the canonical constants include their "; version=..." parameter
		case harbor.MimeTypeSecurityVulnReport:
			return harbor.MimeTypeSecurityVulnReport, true
		case harbor.MimeTypeLegacyVulnReport:
			return harbor.MimeTypeLegacyVulnReport, true
		case harbor.MimeTypeSecuritySBOMReport:
			return harbor.MimeTypeSecuritySBOMReport, true
		}
		if i := strings.IndexByte(part, ';'); i >= 0 { // also match on the base type
			part = strings.TrimSpace(part[:i])
		}
		if part == "*/*" {
			return harbor.MimeTypeSecurityVulnReport, true
		}
	}
	return "", false
}

// writeError answers with a MimeTypeError envelope.
func (s *Server) writeError(w http.ResponseWriter, code int, message string) {
	writeJSON(w, code, harbor.MimeTypeError, harbor.ErrorResponse{Error: harbor.Error{Message: message}})
}

func writeJSON(w http.ResponseWriter, code int, contentType string, payload any) {
	data, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(code)
	_, _ = w.Write(data)
	_, _ = w.Write([]byte{'\n'})
}
