package grype

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/TechPrototyper/harbor-scanner-grype/pkg/harbor"
)

type fakeExec struct {
	stdout  []byte
	err     error
	delay   time.Duration
	gotName string
	gotArgs []string
	gotEnv  []string
	calls   int
}

func (f *fakeExec) Run(ctx context.Context, name string, args []string, env []string) ([]byte, error) {
	f.calls++
	f.gotName, f.gotArgs, f.gotEnv = name, args, env
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return f.stdout, f.err
}

func basicReq(auth string) harbor.ScanRequest {
	return harbor.ScanRequest{
		Registry: harbor.Registry{URL: "https://harbor.example:8443/", Authorization: auth},
		Artifact: harbor.Artifact{Repository: "lib/app", Digest: "sha256:0000", MimeType: harbor.MimeTypeOCIArtifact},
	}
}

func envValue(env []string, key string) (string, bool) {
	for _, e := range env {
		if strings.HasPrefix(e, key+"=") {
			return strings.TrimPrefix(e, key+"="), true
		}
	}
	return "", false
}

func TestImageRef(t *testing.T) {
	ref, err := ImageRef(basicReq(""))
	if err != nil {
		t.Fatal(err)
	}
	if ref != "harbor.example:8443/lib/app@sha256:0000" {
		t.Fatalf("ref = %q", ref)
	}
	if _, err := ImageRef(harbor.ScanRequest{}); err == nil {
		t.Fatal("empty request must be an error")
	}
	if _, err := ImageRef(harbor.ScanRequest{Registry: harbor.Registry{URL: "http://h"}, Artifact: harbor.Artifact{Repository: "r"}}); err == nil {
		t.Fatal("missing digest must be an error")
	}
}

func TestNewCLIRunnerDefaults(t *testing.T) {
	r := NewCLIRunner(CLIOptions{})
	if r.Opts.Path != "grype" || r.Opts.Timeout != 5*time.Minute || r.Exec == nil {
		t.Fatalf("defaults not applied: %+v", r.Opts)
	}
	if _, ok := r.Exec.(OSExecer); !ok {
		t.Fatalf("default Exec must be OSExecer, got %T", r.Exec)
	}
}

func TestBuildCommandBasicAuth(t *testing.T) {
	r := NewCLIRunner(CLIOptions{})
	cred := base64.StdEncoding.EncodeToString([]byte("robot$scanner:s3cr3t"))
	cmd, err := r.BuildCommand(basicReq("Basic " + cred))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(cmd.Args, " ") != "registry:harbor.example:8443/lib/app@sha256:0000 -o json" {
		t.Fatalf("args = %v", cmd.Args)
	}
	for key, want := range map[string]string{
		EnvAuthAuthority:  "harbor.example:8443",
		EnvAuthUsername:   "robot$scanner",
		EnvAuthPassword:   "s3cr3t",
		EnvDBAutoUpdate:   "false",
		EnvCheckAppUpdate: "false",
	} {
		if got, ok := envValue(cmd.Env, key); !ok || got != want {
			t.Errorf("%s = %q (present=%v), want %q", key, got, ok, want)
		}
	}
	if _, ok := envValue(cmd.Env, EnvAuthToken); ok {
		t.Errorf("token must not be set for Basic auth")
	}
	if _, ok := envValue(cmd.Env, EnvInsecureSkipTLS); ok {
		t.Errorf("insecure flag must be absent by default")
	}
}

func TestBuildCommandBearerAndFlags(t *testing.T) {
	r := NewCLIRunner(CLIOptions{InsecureSkipTLS: true, UseHTTP: true, DBAutoUpdate: true})
	cmd, err := r.BuildCommand(basicReq("Bearer tok.en"))
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		EnvAuthToken:       "tok.en",
		EnvInsecureSkipTLS: "true",
		EnvInsecureHTTP:    "true",
		EnvDBAutoUpdate:    "true",
	} {
		if got, ok := envValue(cmd.Env, key); !ok || got != want {
			t.Errorf("%s = %q (present=%v), want %q", key, got, ok, want)
		}
	}
	if _, ok := envValue(cmd.Env, EnvAuthUsername); ok {
		t.Errorf("username must not be set for Bearer auth")
	}
}

func TestBuildCommandAnonymousAndBadScheme(t *testing.T) {
	r := NewCLIRunner(CLIOptions{})
	cmd, err := r.BuildCommand(basicReq(""))
	if err != nil {
		t.Fatalf("anonymous must be allowed: %v", err)
	}
	if _, ok := envValue(cmd.Env, EnvAuthUsername); ok {
		t.Errorf("no credentials expected")
	}
	if _, err := r.BuildCommand(basicReq("Digest abc")); err == nil {
		t.Fatal("unknown auth scheme must be rejected")
	}
	if _, err := r.BuildCommand(basicReq("Basic %%%notbase64")); err == nil {
		t.Fatal("invalid base64 must be rejected")
	}
	if _, err := r.BuildCommand(basicReq("Basic " + base64.StdEncoding.EncodeToString([]byte("nocolon")))); err == nil {
		t.Fatal("Basic credential without colon must be rejected")
	}
}

func TestScanParsesDocument(t *testing.T) {
	raw, err := os.ReadFile("testdata/grype-sample.json")
	if err != nil {
		t.Fatal(err)
	}
	fe := &fakeExec{stdout: raw}
	r := NewCLIRunner(CLIOptions{Path: "/opt/grype"})
	r.Exec = fe
	doc, err := r.Scan(context.Background(), basicReq(""))
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Matches) != 4 || doc.Descriptor.Version != "0.121.2" {
		t.Fatalf("document not parsed: %d matches, version %q", len(doc.Matches), doc.Descriptor.Version)
	}
	if fe.gotName != "/opt/grype" || fe.calls != 1 {
		t.Fatalf("binary path not used: %q calls=%d", fe.gotName, fe.calls)
	}
}

func TestScanErrors(t *testing.T) {
	r := NewCLIRunner(CLIOptions{})
	r.Exec = &fakeExec{err: errors.New("exit status 1: db is corrupt")}
	if _, err := r.Scan(context.Background(), basicReq("")); err == nil || !strings.Contains(err.Error(), "db is corrupt") {
		t.Fatalf("exec error must be wrapped with stderr, got %v", err)
	}
	r.Exec = &fakeExec{stdout: []byte("this is not json")}
	if _, err := r.Scan(context.Background(), basicReq("")); err == nil {
		t.Fatal("non-JSON output must be an error")
	}
	r.Exec = &fakeExec{stdout: []byte("{}")}
	if _, err := r.Scan(context.Background(), basicReq("Digest x")); err == nil {
		t.Fatal("BuildCommand errors must surface from Scan")
	}
}

func TestScanTimeout(t *testing.T) {
	r := NewCLIRunner(CLIOptions{Timeout: 50 * time.Millisecond})
	r.Exec = &fakeExec{stdout: []byte("{}"), delay: 2 * time.Second}
	start := time.Now()
	_, err := r.Scan(context.Background(), basicReq(""))
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want DeadlineExceeded, got %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("timeout not enforced")
	}
}

func TestVersion(t *testing.T) {
	r := NewCLIRunner(CLIOptions{})
	fe := &fakeExec{stdout: []byte(`{"application":"grype","version":"0.121.2","gitCommit":"abc","supportedDbSchema":6,"db":{"built":"2026-09-06T01:31:12Z"}}`)}
	r.Exec = fe
	v, built, err := r.Version(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v != "0.121.2" {
		t.Errorf("version = %q", v)
	}
	if !built.Equal(time.Date(2026, 9, 6, 1, 31, 12, 0, time.UTC)) {
		t.Errorf("db built = %v", built)
	}
	if strings.Join(fe.gotArgs, " ") != "version -o json" {
		t.Errorf("args = %v", fe.gotArgs)
	}
	// missing db section is not an error, just a zero time
	r.Exec = &fakeExec{stdout: []byte(`{"version":"0.113.0"}`)}
	v, built, err = r.Version(context.Background())
	if err != nil || v != "0.113.0" || !built.IsZero() {
		t.Errorf("got %q %v %v", v, built, err)
	}
}

func TestOSExecerRealProcess(t *testing.T) {
	out, err := (OSExecer{}).Run(context.Background(), "sh", []string{"-c", "printf hello; echo $ADAPTER_TEST_ENV"}, []string{"ADAPTER_TEST_ENV=world"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(out)) != "helloworld" {
		t.Fatalf("stdout = %q", out)
	}
	_, err = (OSExecer{}).Run(context.Background(), "sh", []string{"-c", "echo boom >&2; exit 3"}, nil)
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("stderr must be part of the error, got %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	begin := time.Now()
	if _, err := (OSExecer{}).Run(ctx, "sleep", []string{"5"}, nil); err == nil {
		t.Fatal("cancelled context must abort the process")
	}
	if d := time.Since(begin); d > 3*time.Second {
		t.Fatalf("process was not killed on cancel (took %v)", d)
	}
}

func TestOSExecerStdoutLimit(t *testing.T) {
	e := OSExecer{MaxStdoutBytes: 1024}
	begin := time.Now()
	// Endless output: must be killed once the cap is exceeded.
	_, err := e.Run(context.Background(), "sh", []string{"-c", "yes"}, nil)
	if !errors.Is(err, ErrOutputLimit) || !strings.Contains(err.Error(), "output exceeds limit") {
		t.Fatalf("want ErrOutputLimit, got %v", err)
	}
	if time.Since(begin) > 5*time.Second {
		t.Fatal("process not killed when limit exceeded")
	}
	// At or under the cap is fine.
	out, err := e.Run(context.Background(), "sh", []string{"-c", "printf abc"}, nil)
	if err != nil || string(out) != "abc" {
		t.Fatalf("under limit: %q %v", out, err)
	}
}

func TestOSExecerStderrCapped(t *testing.T) {
	_, err := (OSExecer{}).Run(context.Background(), "sh", []string{"-c", "head -c 300000 /dev/zero | tr '\\0' x >&2; exit 1"}, nil)
	if err == nil {
		t.Fatal("want error")
	}
	if len(err.Error()) > maxStderrBytes+1024 {
		t.Fatalf("stderr not capped: error is %d bytes", len(err.Error()))
	}
}

func TestOSExecerGrandchildHoldingPipeDoesNotHang(t *testing.T) {
	old := execWaitDelay
	execWaitDelay = 200 * time.Millisecond
	defer func() { execWaitDelay = old }()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	begin := time.Now()
	_, err := (OSExecer{}).Run(ctx, "sh", []string{"-c", "sleep 30 & sleep 30"}, nil)
	if err == nil {
		t.Fatal("want error")
	}
	if d := time.Since(begin); d > 5*time.Second {
		t.Fatalf("Run blocked on inherited pipe for %v", d)
	}
}

func TestScanFailureIsSanitized(t *testing.T) {
	r := NewCLIRunner(CLIOptions{Path: "/opt/secret/grype"})
	r.Exec = &fakeExec{err: errors.New("run /opt/secret/grype: exit status 1: stderr: db is corrupt")}
	_, err := r.Scan(context.Background(), basicReq(""))
	if err == nil || !strings.Contains(err.Error(), "db is corrupt") {
		t.Fatalf("full error must keep detail for logs, got %v", err)
	}
	if got := PublicMessage(err, "x"); got != "grype scan failed" {
		t.Fatalf("public = %q", got)
	}
	r.Opts.Timeout = 20 * time.Millisecond
	r.Exec = &fakeExec{delay: time.Minute}
	_, err = r.Scan(context.Background(), basicReq(""))
	if got := PublicMessage(err, "x"); got != "grype scan failed: timed out after 20ms" {
		t.Fatalf("public = %q", got)
	}
}
