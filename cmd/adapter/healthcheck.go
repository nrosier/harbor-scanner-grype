package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// healthcheckCommand is the first argument that switches the binary into
// probe mode: `/adapter healthcheck`. The runtime image is distroless (no
// shell, no curl), so a container HEALTHCHECK needs the binary itself.
const healthcheckCommand = "healthcheck"

// healthcheckTimeout bounds the probe request (chosen value).
const healthcheckTimeout = 5 * time.Second

// healthcheckURL builds the /readyz URL for a listen address such as ":8080"
// or "0.0.0.0:8080" (loopback is used when the host is empty or unspecified).
func healthcheckURL(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("SCANNER_API_ADDR %q: %w", addr, err)
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/readyz", nil
}

// runHealthcheck GETs /readyz of the local adapter and returns the process
// exit code: 0 when ready (200), 1 otherwise.
func runHealthcheck(getenv func(string) string, stdout, stderr io.Writer) int {
	return probe(getenv, &http.Client{Timeout: healthcheckTimeout}, stdout, stderr)
}

func probe(getenv func(string) string, client *http.Client, stdout, stderr io.Writer) int {
	addr := getenv("SCANNER_API_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	url, err := healthcheckURL(addr)
	if err != nil {
		fmt.Fprintln(stderr, "healthcheck:", err)
		return 1
	}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintln(stderr, "healthcheck:", err)
		return 1
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(stderr, "healthcheck: %s -> %d %s\n", url, resp.StatusCode, strings.TrimSpace(string(body)))
		return 1
	}
	fmt.Fprintln(stdout, "ok")
	return 0
}
