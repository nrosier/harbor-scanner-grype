package config

import (
	"testing"
	"time"
)

func env(m map[string]string) Getenv { return func(k string) string { return m[k] } }

func TestDefaults(t *testing.T) {
	c, err := Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	want := Config{Addr: ":8080", GrypePath: "grype", SyftPath: "syft", ScanTimeout: 5 * time.Minute, JobTTL: time.Hour,
		CleanupInterval: 5 * time.Minute, PreferCVE: true, LogLevel: "info", WorkerConcurrency: 2, DBUpdateInterval: 24 * time.Hour}
	if c != want {
		t.Fatalf("defaults = %+v, want %+v", c, want)
	}
}

func TestOverrides(t *testing.T) {
	c, err := Load(env(map[string]string{
		"SCANNER_API_ADDR": ":9000", "SCANNER_GRYPE_PATH": "/opt/grype", "SCANNER_SYFT_PATH": "/opt/syft", "SCANNER_SCAN_TIMEOUT": "90s",
		"SCANNER_JOB_TTL": "0", "SCANNER_CLEANUP_INTERVAL": "1m", "SCANNER_REGISTRY_INSECURE_SKIP_TLS": "TRUE",
		"SCANNER_REGISTRY_USE_HTTP": "1", "SCANNER_GRYPE_DB_AUTO_UPDATE": "true", "SCANNER_PREFER_CVE": "false",
		"SCANNER_LOG_LEVEL": "debug", "SCANNER_WORKER_CONCURRENCY": "4", "SCANNER_DB_UPDATE_INTERVAL": "6h",
	}))
	if err != nil {
		t.Fatal(err)
	}
	want := Config{Addr: ":9000", GrypePath: "/opt/grype", SyftPath: "/opt/syft", ScanTimeout: 90 * time.Second, JobTTL: 0,
		CleanupInterval: time.Minute, InsecureSkipTLS: true, UseHTTP: true, DBAutoUpdate: true, PreferCVE: false, LogLevel: "debug", WorkerConcurrency: 4, DBUpdateInterval: 6 * time.Hour}
	if c != want {
		t.Fatalf("got %+v, want %+v", c, want)
	}
}

func TestInvalidValues(t *testing.T) {
	for k, v := range map[string]string{
		"SCANNER_SCAN_TIMEOUT":               "soon",
		"SCANNER_REGISTRY_INSECURE_SKIP_TLS": "yes",
		"SCANNER_LOG_LEVEL":                  "loud",
		"SCANNER_WORKER_CONCURRENCY":         "many",
	} {
		if _, err := Load(env(map[string]string{k: v})); err == nil {
			t.Errorf("%s=%q must be rejected", k, v)
		}
	}
}

func TestWorkerConcurrencyRejectsNonPositive(t *testing.T) {
	for _, v := range []string{"0", "-1", "-5", "1.5", "two", " 2"} {
		if _, err := Load(env(map[string]string{"SCANNER_WORKER_CONCURRENCY": v})); err == nil {
			t.Errorf("SCANNER_WORKER_CONCURRENCY=%q must be rejected", v)
		}
	}
	c, err := Load(env(map[string]string{"SCANNER_WORKER_CONCURRENCY": "1"}))
	if err != nil || c.WorkerConcurrency != 1 {
		t.Fatalf("got %+v, %v", c, err)
	}
}

func TestDBUpdateInterval(t *testing.T) {
	for in, want := range map[string]time.Duration{"": 24 * time.Hour, "0": 0, "0s": 0, "90m": 90 * time.Minute, "1h30m": 90 * time.Minute} {
		c, err := Load(env(map[string]string{"SCANNER_DB_UPDATE_INTERVAL": in}))
		if err != nil || c.DBUpdateInterval != want {
			t.Errorf("SCANNER_DB_UPDATE_INTERVAL=%q: got %v, %v; want %v", in, c.DBUpdateInterval, err, want)
		}
	}
	for _, v := range []string{"-1h", "-1ns", "daily", "24", "1d"} {
		if _, err := Load(env(map[string]string{"SCANNER_DB_UPDATE_INTERVAL": v})); err == nil {
			t.Errorf("SCANNER_DB_UPDATE_INTERVAL=%q must be rejected", v)
		}
	}
}
