// Package api implements the HTTP surface of the Harbor Pluggable
// Scanner Adapter API v1.0 on top of job.Store and grype.Runner.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
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
}

// Server wires handlers, store and runner. Scans run in goroutines:
// POST /scan creates a Pending job, starts the scan, and returns 202.
type Server struct {
	opts   Options
	store  job.Store
	runner grype.Runner
	mux    *http.ServeMux
}

// New builds a Server. Routes (all under BasePath):
//
//	GET  /metadata          -> 200 MimeTypeMetadata
//	POST /scan              -> 202 MimeTypeScanResponse | 400 bad json | 422 unsupported artifact mime
//	GET  /scan/{id}/report  -> 302 (+Location, Refresh-After) while Pending/Running
//	                           200 report (Content-Type = negotiated) when Finished
//	                           500 MimeTypeError when Failed
//	                           404 MimeTypeError when unknown
//	                           400 MimeTypeError when Accept is unsupported
//
// and GET /healthz -> 200 "ok" (outside BasePath). Accept negotiation:
// "", "*/*" and MimeTypeSecurityVulnReport -> MimeTypeSecurityVulnReport;
// MimeTypeLegacyVulnReport -> MimeTypeLegacyVulnReport; anything else -> 400.
// Multiple comma-separated Accept values: first supported one wins.
func New(opts Options, store job.Store, runner grype.Runner) *Server {
	if opts.RefreshAfter <= 0 {
		opts.RefreshAfter = 15
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	s := &Server{opts: opts, store: store, runner: runner, mux: http.NewServeMux()}
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

// Metadata assembles the /metadata document.
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
	return harbor.ScannerAdapterMetadata{
		Scanner: s.opts.Scanner,
		Capabilities: []harbor.Capability{{
			ConsumesMimeTypes: []string{harbor.MimeTypeOCIArtifact, harbor.MimeTypeDockerArtifact},
			ProducesMimeTypes: []string{harbor.MimeTypeSecurityVulnReport, harbor.MimeTypeLegacyVulnReport},
		}},
		Properties: props,
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
	j, err := s.store.Create(req)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "create job: "+err.Error())
		return
	}
	go s.runScan(j)
	writeJSON(w, http.StatusAccepted, harbor.MimeTypeScanResponse, harbor.ScanResponse{ID: j.ID})
}

// runScan drives one job to Finished or Failed. It runs in its own
// goroutine; panics are recovered and stored as job errors.
func (s *Server) runScan(j *job.Job) {
	defer func() {
		if p := recover(); p != nil {
			_ = s.store.SetError(j.ID, fmt.Sprintf("scan panicked: %v", p))
		}
	}()
	if err := s.store.SetRunning(j.ID); err != nil {
		return // the job was cleaned up before the scan started
	}
	log := s.opts.Logger.With("job", j.ID, "repository", j.Request.Artifact.Repository, "digest", j.Request.Artifact.Digest)
	log.Info("scan started")
	start := time.Now()
	doc, err := s.runner.Scan(context.Background(), j.Request)
	if err != nil {
		log.Error("scan failed", "error", err.Error(), "duration", time.Since(start).String())
		_ = s.store.SetError(j.ID, err.Error())
		return
	}
	mapper := &grype.Mapper{Options: s.opts.MapperOptions, Scanner: s.opts.Scanner, Now: time.Now}
	report := mapper.Map(doc, j.Request.Artifact)
	_ = s.store.SetReport(j.ID, report)
	log.Info("scan finished", "severity", string(report.Severity), "findings", len(report.Vulnerabilities),
		"matches", len(doc.Matches), "duration", time.Since(start).String())
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	j, err := s.store.Get(r.PathValue("id"))
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
		w.Header().Set("Location", r.URL.Path)
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
	mime, ok := negotiateReportMime(r.Header.Get("Accept"))
	if !ok {
		s.writeError(w, http.StatusBadRequest, "unsupported Accept header: "+r.Header.Get("Accept"))
		return
	}
	writeJSON(w, http.StatusOK, mime, j.Report)
}

// negotiateReportMime picks the report MIME type for an Accept header:
// "" and "*/*" default to the v1.1 security report; among several
// comma-separated values the first supported one wins.
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
