package main

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthcheckURL(t *testing.T) {
	for in, want := range map[string]string{
		":8080":          "http://127.0.0.1:8080/readyz",
		"0.0.0.0:9000":   "http://127.0.0.1:9000/readyz",
		"[::]:9000":      "http://127.0.0.1:9000/readyz",
		"10.1.2.3:8080":  "http://10.1.2.3:8080/readyz",
		"localhost:8081": "http://localhost:8081/readyz",
	} {
		got, err := healthcheckURL(in)
		if err != nil || got != want {
			t.Errorf("healthcheckURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := healthcheckURL("8080"); err == nil {
		t.Error("an address without a port must be rejected")
	}
}

func serveOn(t *testing.T, code int) (addr string) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/readyz" {
			t.Errorf("path = %q, want /readyz", r.URL.Path)
		}
		w.WriteHeader(code)
		w.Write([]byte("body"))
	}))
	srv.Listener.Close()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv.Listener = l
	srv.Start()
	t.Cleanup(srv.Close)
	return l.Addr().String()
}

func TestHealthcheckExitCodes(t *testing.T) {
	for _, tc := range []struct {
		code, want int
	}{{200, 0}, {503, 1}, {500, 1}} {
		addr := serveOn(t, tc.code)
		var out, errb bytes.Buffer
		got := runHealthcheck(func(string) string { return addr }, &out, &errb)
		if got != tc.want {
			t.Errorf("status %d: exit %d, want %d (stderr %q)", tc.code, got, tc.want, errb.String())
		}
	}
}

func TestHealthcheckConnectionRefused(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	var out, errb bytes.Buffer
	if got := runHealthcheck(func(string) string { return addr }, &out, &errb); got != 1 {
		t.Fatalf("exit %d, want 1", got)
	}
}
