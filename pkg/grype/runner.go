package grype

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/TechPrototyper/harbor-scanner-grype/pkg/harbor"
)

// Execer runs an external command. Abstracted so tests can fake the
// Grype binary. Implementations must honour ctx cancellation and return
// stdout; on non-zero exit they return stderr inside the error.
type Execer interface {
	Run(ctx context.Context, name string, args []string, env []string) (stdout []byte, err error)
}

// ErrOutputLimit is returned (wrapped) by OSExecer when a command writes more
// than OSExecer.MaxStdoutBytes to stdout; the process is killed.
var ErrOutputLimit = errors.New("output exceeds limit")

// maxStderrBytes caps how much stderr OSExecer retains per command.
const maxStderrBytes = 64 << 10

// execWaitDelay bounds how long Run waits for I/O pipes to close after the
// context is cancelled and the process killed (grandchildren may hold them).
// A variable so tests can shorten it.
var execWaitDelay = 5 * time.Second

// Failure is a scan/SBOM error that carries a bounded, sanitized message
// safe to hand to Harbor. Error() is the full detail for server-side logs
// only (it may contain binary paths and stderr).
type Failure struct {
	Public string // stable short message; no paths, no tool output
	Err    error
}

func (f *Failure) Error() string { return f.Err.Error() }
func (f *Failure) Unwrap() error { return f.Err }

// PublicMessage returns the sanitized message of the first Failure in err's
// chain, or fallback if there is none.
func PublicMessage(err error, fallback string) string {
	var f *Failure
	if errors.As(err, &f) && f.Public != "" {
		return f.Public
	}
	return fallback
}

// publicFailure builds the Failure for a failed Exec call. what is the stable
// base message ("grype scan failed"); timeout is the configured limit.
func publicFailure(ctx context.Context, what string, timeout time.Duration, err error) *Failure {
	pub := what
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		pub = fmt.Sprintf("%s: timed out after %s", what, timeout)
	case errors.Is(err, ErrOutputLimit):
		pub = what + ": output exceeds limit"
	}
	return &Failure{Public: pub, Err: err}
}

// OSExecer runs real processes via os/exec.
type OSExecer struct {
	// MaxStdoutBytes, if > 0, bounds retained stdout: once exceeded the
	// process is killed and Run fails with ErrOutputLimit.
	MaxStdoutBytes int64
}

// limitWriter buffers up to max bytes. In fail mode, exceeding max cancels
// the command and fails the write; otherwise extra bytes are discarded
// (still reported as written so the child never blocks on a full pipe).
type limitWriter struct {
	buf      bytes.Buffer
	max      int64
	fail     bool
	cancel   context.CancelFunc
	exceeded bool
}

func (w *limitWriter) Write(p []byte) (int, error) {
	if room := w.max - int64(w.buf.Len()); int64(len(p)) > room {
		if w.fail {
			w.exceeded = true
			w.cancel()
			return 0, ErrOutputLimit
		}
		if room > 0 {
			w.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return w.buf.Write(p)
}

// Run executes name with args, environment = os.Environ() + env. The error
// text includes (bounded) stderr and is for logs only.
func (e OSExecer) Run(ctx context.Context, name string, args []string, env []string) ([]byte, error) {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(runCtx, name, args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.WaitDelay = execWaitDelay
	stdout := &limitWriter{max: e.MaxStdoutBytes, fail: e.MaxStdoutBytes > 0, cancel: cancel}
	if e.MaxStdoutBytes <= 0 {
		stdout.max = 1<<63 - 1
	}
	stderr := &limitWriter{max: maxStderrBytes}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		if stdout.exceeded {
			return nil, fmt.Errorf("run %s: stdout exceeds %d bytes: %w", name, e.MaxStdoutBytes, ErrOutputLimit)
		}
		if ctx.Err() != nil {
			err = fmt.Errorf("%w (%w)", err, ctx.Err())
		}
		return nil, fmt.Errorf("run %s: %w: stderr: %s", name, err, stderr.buf.String())
	}
	return stdout.buf.Bytes(), nil
}

// Runner scans an artifact and returns Grype's Document.
type Runner interface {
	Scan(ctx context.Context, req harbor.ScanRequest) (*Document, error)
	// Version returns the Grype version and vulnerability DB build time
	// (both may be empty if unknown). Used for /metadata.
	Version(ctx context.Context) (version string, dbBuilt time.Time, err error)
}

// CLIOptions configure the CLI runner.
type CLIOptions struct {
	Path            string        // grype binary, default "grype"
	Timeout         time.Duration // per scan, default 5m
	InsecureSkipTLS bool          // GRYPE_REGISTRY_INSECURE_SKIP_TLS_VERIFY
	UseHTTP         bool          // GRYPE_REGISTRY_INSECURE_USE_HTTP
	DBAutoUpdate    bool          // GRYPE_DB_AUTO_UPDATE (default false: DB is refreshed by the container/cron, not per scan)
}

// CLIRunner shells out to the grype binary.
type CLIRunner struct {
	Opts CLIOptions
	Exec Execer
}

// NewCLIRunner applies defaults (Path "grype", Timeout 5m, OSExecer).
func NewCLIRunner(opts CLIOptions) *CLIRunner {
	if opts.Path == "" {
		opts.Path = "grype"
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Minute
	}
	return &CLIRunner{Opts: opts, Exec: OSExecer{}}
}

// Command is what BuildCommand produces: the argv and the extra
// environment for one scan.
type Command struct {
	Args []string
	Env  []string
}

// Environment variable names understood by grype.
const (
	EnvAuthAuthority   = "GRYPE_REGISTRY_AUTH_AUTHORITY"
	EnvAuthUsername    = "GRYPE_REGISTRY_AUTH_USERNAME"
	EnvAuthPassword    = "GRYPE_REGISTRY_AUTH_PASSWORD"
	EnvAuthToken       = "GRYPE_REGISTRY_AUTH_TOKEN"
	EnvInsecureSkipTLS = "GRYPE_REGISTRY_INSECURE_SKIP_TLS_VERIFY"
	EnvInsecureHTTP    = "GRYPE_REGISTRY_INSECURE_USE_HTTP"
	EnvDBAutoUpdate    = "GRYPE_DB_AUTO_UPDATE"
	EnvCheckAppUpdate  = "GRYPE_CHECK_FOR_APP_UPDATE"
)

// registryParts returns the registry host (scheme and path stripped) and
// the full image ref "<host>/<repository>@<digest>" for a scan request.
func registryParts(req harbor.ScanRequest) (host, ref string, err error) {
	u, err := url.Parse(req.Registry.URL)
	if err != nil || u.Host == "" {
		return "", "", errors.New("scan request: registry URL must contain a host")
	}
	if req.Artifact.Repository == "" {
		return "", "", errors.New("scan request: artifact repository is required")
	}
	if req.Artifact.Digest == "" {
		return "", "", errors.New("scan request: artifact digest is required")
	}
	host = u.Host
	ref = host + "/" + req.Artifact.Repository + "@" + req.Artifact.Digest
	return host, ref, nil
}

// ImageRef builds "<host>/<repository>@<digest>" from a request. The
// registry URL's scheme is stripped; a trailing slash is ignored.
func ImageRef(req harbor.ScanRequest) (string, error) {
	_, ref, err := registryParts(req)
	return ref, err
}

// BuildCommand turns a scan request into grype argv + env:
//
//	args: registry:<ImageRef> -o json
//	env:  GRYPE_REGISTRY_AUTH_AUTHORITY=<host>
//	      Basic <b64(user:pass)> -> GRYPE_REGISTRY_AUTH_USERNAME/PASSWORD
//	      Bearer <token>         -> GRYPE_REGISTRY_AUTH_TOKEN
//	      GRYPE_DB_AUTO_UPDATE=<true|false>, GRYPE_CHECK_FOR_APP_UPDATE=false
//	      GRYPE_REGISTRY_INSECURE_SKIP_TLS_VERIFY=true if InsecureSkipTLS
//	      GRYPE_REGISTRY_INSECURE_USE_HTTP=true if UseHTTP
//
// An empty Authorization is allowed (anonymous pull). Any other scheme
// is an error.
func (r *CLIRunner) BuildCommand(req harbor.ScanRequest) (Command, error) {
	host, ref, err := registryParts(req)
	if err != nil {
		return Command{}, err
	}
	cmd := Command{Args: []string{"registry:" + ref, "-o", "json"}}
	env := []string{
		EnvAuthAuthority + "=" + host,
		EnvDBAutoUpdate + "=" + strconv.FormatBool(r.Opts.DBAutoUpdate),
		EnvCheckAppUpdate + "=false",
	}
	switch scheme, credential := splitAuth(req.Registry.Authorization); strings.ToLower(scheme) {
	case "": // anonymous pull, no credential env
	case "basic":
		userPass, err := base64.StdEncoding.DecodeString(credential)
		if err != nil {
			return Command{}, fmt.Errorf("scan request: invalid Basic credential: %w", err)
		}
		user, pass, ok := strings.Cut(string(userPass), ":")
		if !ok {
			return Command{}, errors.New("scan request: Basic credential must be <user>:<password>")
		}
		env = append(env, EnvAuthUsername+"="+user, EnvAuthPassword+"="+pass)
	case "bearer":
		env = append(env, EnvAuthToken+"="+credential)
	default:
		// Never echo the value: without a space the "scheme" is the whole
		// Authorization header, i.e. possibly a bare credential, and this
		// error reaches logs and Harbor's 500 body.
		return Command{}, errors.New("scan request: unsupported authorization scheme")
	}
	if r.Opts.InsecureSkipTLS {
		env = append(env, EnvInsecureSkipTLS+"=true")
	}
	if r.Opts.UseHTTP {
		env = append(env, EnvInsecureHTTP+"=true")
	}
	cmd.Env = env
	return cmd, nil
}

// splitAuth splits an HTTP Authorization header value into its scheme and
// credential ("Basic abc" -> "Basic", "abc"); an empty value yields "".
func splitAuth(auth string) (scheme, credential string) {
	if i := strings.IndexByte(auth, ' '); i >= 0 {
		return auth[:i], auth[i+1:]
	}
	return auth, ""
}

// Scan runs grype with a timeout (Opts.Timeout) and parses the JSON.
func (r *CLIRunner) Scan(ctx context.Context, req harbor.ScanRequest) (*Document, error) {
	cmd, err := r.BuildCommand(req)
	if err != nil {
		return nil, err
	}
	scanCtx := ctx
	if r.Opts.Timeout > 0 {
		var cancel context.CancelFunc
		scanCtx, cancel = context.WithTimeout(ctx, r.Opts.Timeout)
		defer cancel()
	}
	out, err := r.Exec.Run(scanCtx, r.Opts.Path, cmd.Args, cmd.Env)
	if err != nil {
		return nil, publicFailure(scanCtx, "grype scan failed", r.Opts.Timeout, fmt.Errorf("grype scan: %w", err))
	}
	var doc Document
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, &Failure{Public: "grype scan failed: unreadable output", Err: fmt.Errorf("grype scan: decode output: %w", err)}
	}
	return &doc, nil
}

// versionOutput is the subset of `grype version -o json` we consume.
type versionOutput struct {
	Version string `json:"version"`
	DB      struct {
		Built string `json:"built"`
	} `json:"db"`
}

// Version runs `grype version -o json` and returns version + DB built time.
func (r *CLIRunner) Version(ctx context.Context) (string, time.Time, error) {
	out, err := r.Exec.Run(ctx, r.Opts.Path, []string{"version", "-o", "json"}, nil)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("grype version: %w", err)
	}
	var vo versionOutput
	if err := json.Unmarshal(out, &vo); err != nil {
		return "", time.Time{}, fmt.Errorf("grype version: decode output: %w", err)
	}
	built := time.Time{}
	if t, err := time.Parse(time.RFC3339, vo.DB.Built); err == nil {
		built = t
	}
	return vo.Version, built, nil
}
