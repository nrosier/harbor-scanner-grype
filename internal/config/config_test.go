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
	want := Config{Addr: ":8080", GrypePath: "grype", ScanTimeout: 5 * time.Minute, JobTTL: time.Hour,
		CleanupInterval: 5 * time.Minute, PreferCVE: true, LogLevel: "info"}
	if c != want {
		t.Fatalf("defaults = %+v, want %+v", c, want)
	}
}

func TestOverrides(t *testing.T) {
	c, err := Load(env(map[string]string{
		"SCANNER_API_ADDR": ":9000", "SCANNER_GRYPE_PATH": "/opt/grype", "SCANNER_SCAN_TIMEOUT": "90s",
		"SCANNER_JOB_TTL": "0", "SCANNER_CLEANUP_INTERVAL": "1m", "SCANNER_REGISTRY_INSECURE_SKIP_TLS": "TRUE",
		"SCANNER_REGISTRY_USE_HTTP": "1", "SCANNER_GRYPE_DB_AUTO_UPDATE": "true", "SCANNER_PREFER_CVE": "false",
		"SCANNER_LOG_LEVEL": "debug",
	}))
	if err != nil {
		t.Fatal(err)
	}
	want := Config{Addr: ":9000", GrypePath: "/opt/grype", ScanTimeout: 90 * time.Second, JobTTL: 0,
		CleanupInterval: time.Minute, InsecureSkipTLS: true, UseHTTP: true, DBAutoUpdate: true, PreferCVE: false, LogLevel: "debug"}
	if c != want {
		t.Fatalf("got %+v, want %+v", c, want)
	}
}

func TestInvalidValues(t *testing.T) {
	for k, v := range map[string]string{
		"SCANNER_SCAN_TIMEOUT":               "soon",
		"SCANNER_REGISTRY_INSECURE_SKIP_TLS": "yes",
		"SCANNER_LOG_LEVEL":                  "loud",
	} {
		if _, err := Load(env(map[string]string{k: v})); err == nil {
			t.Errorf("%s=%q must be rejected", k, v)
		}
	}
}
