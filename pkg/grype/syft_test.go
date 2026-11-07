package grype

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func newTestSyft(opts SyftOptions, f *fakeExec) *SyftRunner {
	r := NewSyftRunner(opts)
	r.Exec = f
	return r
}

func TestNewSyftRunnerDefaults(t *testing.T) {
	r := NewSyftRunner(SyftOptions{})
	if r.Opts.Path != "syft" || r.Opts.Timeout != 5*time.Minute {
		t.Fatalf("defaults not applied: %+v", r.Opts)
	}
	if _, ok := r.Exec.(OSExecer); !ok {
		t.Fatalf("default Exec must be OSExecer, got %T", r.Exec)
	}
}

func TestBuildSyftCommand(t *testing.T) {
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	tests := []struct {
		name    string
		opts    SyftOptions
		auth    string
		want    map[string]string
		absent  []string
		wantErr bool
	}{
		{name: "anonymous", want: map[string]string{
			SyftEnvAuthAuthority: "harbor.example:8443", SyftEnvCheckAppUpdate: "false"},
			absent: []string{SyftEnvAuthUsername, SyftEnvAuthPassword, SyftEnvAuthToken, SyftEnvInsecureSkipTLS, SyftEnvInsecureHTTP}},
		{name: "basic", auth: "Basic " + b64("robot$x:p:ss"), want: map[string]string{
			SyftEnvAuthAuthority: "harbor.example:8443", SyftEnvAuthUsername: "robot$x", SyftEnvAuthPassword: "p:ss", SyftEnvCheckAppUpdate: "false"},
			absent: []string{SyftEnvAuthToken}},
		{name: "bearer", auth: "Bearer tok123", want: map[string]string{
			SyftEnvAuthAuthority: "harbor.example:8443", SyftEnvAuthToken: "tok123", SyftEnvCheckAppUpdate: "false"},
			absent: []string{SyftEnvAuthUsername, SyftEnvAuthPassword}},
		{name: "unknown scheme", auth: "Digest abc", wantErr: true},
		{name: "malformed base64", auth: "Basic !!!notbase64", wantErr: true},
		{name: "basic without colon", auth: "Basic " + b64("nocolon"), wantErr: true},
		{name: "insecure tls", opts: SyftOptions{InsecureSkipTLS: true}, want: map[string]string{
			SyftEnvInsecureSkipTLS: "true", SyftEnvCheckAppUpdate: "false"}, absent: []string{SyftEnvInsecureHTTP}},
		{name: "http", opts: SyftOptions{UseHTTP: true}, want: map[string]string{
			SyftEnvInsecureHTTP: "true", SyftEnvCheckAppUpdate: "false"}, absent: []string{SyftEnvInsecureSkipTLS}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, err := NewSyftRunner(tt.opts).BuildSyftCommand(basicReq(tt.auth))
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if strings.Contains(err.Error(), "abc") && tt.auth == "Basic "+b64("nocolon") {
					t.Fatalf("error leaks credential: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			wantArgs := []string{"registry:harbor.example:8443/lib/app@sha256:0000", "-o", "spdx-json", "-q"}
			if strings.Join(cmd.Args, "\x00") != strings.Join(wantArgs, "\x00") {
				t.Fatalf("args = %q, want %q", cmd.Args, wantArgs)
			}
			for k, v := range tt.want {
				if got, ok := envValue(cmd.Env, k); !ok || got != v {
					t.Errorf("%s = %q (present=%v), want %q", k, got, ok, v)
				}
			}
			for _, k := range tt.absent {
				if _, ok := envValue(cmd.Env, k); ok {
					t.Errorf("%s must not be set", k)
				}
			}
			if _, ok := envValue(cmd.Env, SyftEnvCheckAppUpdate); !ok {
				t.Error("SYFT_CHECK_FOR_APP_UPDATE must always be set")
			}
			joined := strings.Join(cmd.Args, " ")
			for _, secret := range []string{"robot$x", "p:ss", "tok123", tt.auth} {
				if secret != "" && strings.Contains(joined, secret) {
					t.Errorf("credential %q leaked into args", secret)
				}
			}
		})
	}
}

func TestGenerateSPDXSuccess(t *testing.T) {
	sample, err := os.ReadFile("testdata/syft-spdx-sample.json")
	if err != nil {
		t.Fatal(err)
	}
	// Odd whitespace + trailing newline must survive untouched.
	body := append([]byte("  "), sample...)
	body = append(body, '\n')
	f := &fakeExec{stdout: body}
	r := newTestSyft(SyftOptions{Path: "/opt/syft"}, f)
	got, err := r.GenerateSPDX(context.Background(), basicReq("Bearer tok123"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatal("returned document is not byte-identical to stdout")
	}
	if f.gotName != "/opt/syft" || f.calls != 1 {
		t.Fatalf("name=%q calls=%d", f.gotName, f.calls)
	}
	if v, _ := envValue(f.gotEnv, SyftEnvAuthToken); v != "tok123" {
		t.Fatalf("token env = %q", v)
	}
}

func TestGenerateSPDXBuildError(t *testing.T) {
	f := &fakeExec{}
	r := newTestSyft(SyftOptions{}, f)
	if _, err := r.GenerateSPDX(context.Background(), basicReq("Digest x")); err == nil {
		t.Fatal("expected error")
	}
	if f.calls != 0 {
		t.Fatal("must not exec on build error")
	}
}

func TestGenerateSPDXExecError(t *testing.T) {
	f := &fakeExec{stdout: []byte("SECRET-STDOUT"), err: os.ErrPermission}
	r := newTestSyft(SyftOptions{}, f)
	_, err := r.GenerateSPDX(context.Background(), basicReq("Basic "+base64.StdEncoding.EncodeToString([]byte("u:hunter2"))))
	if err == nil {
		t.Fatal("expected error")
	}
	for _, s := range []string{"hunter2", "SECRET-STDOUT"} {
		if strings.Contains(err.Error(), s) {
			t.Fatalf("error leaks %q: %v", s, err)
		}
	}
}

func TestGenerateSPDXValidation(t *testing.T) {
	valid := `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"n","documentNamespace":"https://x"}`
	tests := []struct {
		name, out, wantMsg string
	}{
		{"invalid json", "not json SECRET", "valid JSON"},
		{"json array", `[]`, "valid JSON"},
		{"empty", ``, "valid JSON"},
		{"missing spdxVersion", `{"SPDXID":"SPDXRef-DOCUMENT","name":"n","documentNamespace":"x"}`, "spdxVersion"},
		{"wrong version prefix", strings.Replace(valid, "SPDX-2.3", "SPDX-3.0", 1), "spdxVersion"},
		{"missing SPDXID", `{"spdxVersion":"SPDX-2.3","name":"n","documentNamespace":"x"}`, "SPDXID"},
		{"wrong SPDXID", strings.Replace(valid, "SPDXRef-DOCUMENT", "SPDXRef-Other", 1), "SPDXID"},
		{"missing name", `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","documentNamespace":"x"}`, "name"},
		{"missing namespace", `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"n"}`, "documentNamespace"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newTestSyft(SyftOptions{}, &fakeExec{stdout: []byte(tt.out)})
			_, err := r.GenerateSPDX(context.Background(), basicReq(""))
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Fatalf("error %q lacks %q", err, tt.wantMsg)
			}
			if strings.Contains(err.Error(), "SECRET") {
				t.Fatalf("error leaks output body: %v", err)
			}
		})
	}
	r := newTestSyft(SyftOptions{}, &fakeExec{stdout: []byte(valid)})
	if _, err := r.GenerateSPDX(context.Background(), basicReq("")); err != nil {
		t.Fatalf("valid minimal doc rejected: %v", err)
	}
}

func TestGenerateSPDXTimeout(t *testing.T) {
	f := &fakeExec{delay: time.Minute, stdout: []byte("{}")}
	r := newTestSyft(SyftOptions{Timeout: 20 * time.Millisecond}, f)
	start := time.Now()
	_, err := r.GenerateSPDX(context.Background(), basicReq(""))
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err = %v, want timeout", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("timeout not applied")
	}
}

// A bare credential in Authorization (no "<scheme> " prefix) must never be
// echoed into the error: it reaches logs and Harbor's 500 body.
func TestBuildCommandDoesNotEchoBareAuthorization(t *testing.T) {
	const secret = "rawsecrettoken"
	_, e1 := NewSyftRunner(SyftOptions{}).BuildSyftCommand(basicReq(secret))
	_, e2 := NewCLIRunner(CLIOptions{}).BuildCommand(basicReq(secret))
	for name, err := range map[string]error{"syft": e1, "grype": e2} {
		if err == nil {
			t.Fatalf("%s: bare Authorization must be rejected", name)
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("%s: error leaks credential: %v", name, err)
		}
	}
}

func TestGenerateSPDXOutputLimitAndSanitizedMessages(t *testing.T) {
	r := NewSyftRunner(SyftOptions{Path: "sh"})
	r.Exec = OSExecer{MaxStdoutBytes: 512}
	// Drive the real process path via a wrapper command.
	out, err := r.Exec.Run(context.Background(), "sh", []string{"-c", "yes"}, nil)
	_ = out
	if err == nil || !strings.Contains(err.Error(), "output exceeds limit") {
		t.Fatalf("err = %v", err)
	}

	// Default executor carries the SBOM cap.
	if e, ok := NewSyftRunner(SyftOptions{}).Exec.(OSExecer); !ok || e.MaxStdoutBytes != MaxSBOMBytes {
		t.Fatalf("default exec cap = %+v", e)
	}

	// Fake exec exceeding the cap after the fact -> public message.
	big := newTestSyft(SyftOptions{}, &fakeExec{stdout: make([]byte, MaxSBOMBytes+1)})
	_, err = big.GenerateSPDX(context.Background(), basicReq(""))
	if got := PublicMessage(err, ""); got != "syft sbom generation failed: output exceeds limit" {
		t.Fatalf("public = %q (err %v)", got, err)
	}

	// Exec failure with path + stderr never reaches the public message.
	bad := newTestSyft(SyftOptions{}, &fakeExec{err: errors.New("run /usr/bin/syft: exit status 1: stderr: oops")})
	_, err = bad.GenerateSPDX(context.Background(), basicReq(""))
	if got := PublicMessage(err, ""); got != "syft sbom generation failed" {
		t.Fatalf("public = %q", got)
	}

	// Timeout.
	to := newTestSyft(SyftOptions{Timeout: 20 * time.Millisecond}, &fakeExec{delay: time.Minute})
	_, err = to.GenerateSPDX(context.Background(), basicReq(""))
	if got := PublicMessage(err, ""); got != "syft sbom generation failed: timed out after 20ms" {
		t.Fatalf("public = %q", got)
	}
}
