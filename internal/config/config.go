// Package config reads the adapter configuration from environment
// variables. All keys are prefixed SCANNER_.
package config

import (
	"fmt"
	"strings"
	"time"
)

// Configuration keys.
const (
	keyAddr            = "SCANNER_API_ADDR"
	keyGrypePath       = "SCANNER_GRYPE_PATH"
	keyScanTimeout     = "SCANNER_SCAN_TIMEOUT"
	keyJobTTL          = "SCANNER_JOB_TTL"
	keyCleanupInterval = "SCANNER_CLEANUP_INTERVAL"
	keyInsecureSkipTLS = "SCANNER_REGISTRY_INSECURE_SKIP_TLS"
	keyUseHTTP         = "SCANNER_REGISTRY_USE_HTTP"
	keyDBAutoUpdate    = "SCANNER_GRYPE_DB_AUTO_UPDATE"
	keyPreferCVE       = "SCANNER_PREFER_CVE"
	keyLogLevel        = "SCANNER_LOG_LEVEL"
)

// Config of the adapter process.
type Config struct {
	Addr            string        // SCANNER_API_ADDR, default ":8080"
	GrypePath       string        // SCANNER_GRYPE_PATH, default "grype"
	ScanTimeout     time.Duration // SCANNER_SCAN_TIMEOUT, default 5m
	JobTTL          time.Duration // SCANNER_JOB_TTL, default 1h; 0 disables cleanup
	CleanupInterval time.Duration // SCANNER_CLEANUP_INTERVAL, default 5m
	InsecureSkipTLS bool          // SCANNER_REGISTRY_INSECURE_SKIP_TLS, default false
	UseHTTP         bool          // SCANNER_REGISTRY_USE_HTTP, default false
	DBAutoUpdate    bool          // SCANNER_GRYPE_DB_AUTO_UPDATE, default false
	PreferCVE       bool          // SCANNER_PREFER_CVE, default true
	LogLevel        string        // SCANNER_LOG_LEVEL, default "info" (debug|info|warn|error)
}

// Getenv is the lookup function; tests override it. Empty string means unset.
type Getenv func(key string) string

// Load parses the environment. Booleans accept true/false/1/0 (case-
// insensitive); durations use time.ParseDuration. Invalid values are
// errors, never silently defaulted.
func Load(getenv Getenv) (Config, error) {
	c := Config{
		Addr:            ":8080",
		GrypePath:       "grype",
		ScanTimeout:     5 * time.Minute,
		JobTTL:          time.Hour,
		CleanupInterval: 5 * time.Minute,
		PreferCVE:       true,
		LogLevel:        "info",
	}

	if v := getenv(keyAddr); v != "" {
		c.Addr = v
	}
	if v := getenv(keyGrypePath); v != "" {
		c.GrypePath = v
	}

	durations := []struct {
		key string
		dst *time.Duration
	}{
		{keyScanTimeout, &c.ScanTimeout},
		{keyJobTTL, &c.JobTTL},
		{keyCleanupInterval, &c.CleanupInterval},
	}
	for _, d := range durations {
		v := getenv(d.key)
		if v == "" {
			continue
		}
		parsed, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("%s: %w", d.key, err)
		}
		*d.dst = parsed
	}

	bools := []struct {
		key string
		dst *bool
	}{
		{keyInsecureSkipTLS, &c.InsecureSkipTLS},
		{keyUseHTTP, &c.UseHTTP},
		{keyDBAutoUpdate, &c.DBAutoUpdate},
		{keyPreferCVE, &c.PreferCVE},
	}
	for _, b := range bools {
		v := getenv(b.key)
		if v == "" {
			continue
		}
		parsed, err := parseBool(b.key, v)
		if err != nil {
			return Config{}, err
		}
		*b.dst = parsed
	}

	if v := getenv(keyLogLevel); v != "" {
		level := strings.ToLower(v)
		switch level {
		case "debug", "info", "warn", "error":
			c.LogLevel = level
		default:
			return Config{}, fmt.Errorf("%s: invalid level %q (want debug|info|warn|error)", keyLogLevel, v)
		}
	}

	return c, nil
}

func parseBool(key, value string) (bool, error) {
	switch strings.ToLower(value) {
	case "true", "1":
		return true, nil
	case "false", "0":
		return false, nil
	default:
		return false, fmt.Errorf("%s: invalid boolean %q (want true/false/1/0)", key, value)
	}
}
