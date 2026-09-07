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

// OSExecer runs real processes via os/exec.
type OSExecer struct{}

// Run executes name with args, environment = os.Environ() + env.
func (OSExecer) Run(ctx context.Context, name string, args []string, env []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("run %s: %w: stderr: %s", name, err, stderr.String())
	}
	return stdout.Bytes(), nil
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
		return Command{}, fmt.Errorf("scan request: unsupported authorization scheme %q", scheme)
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
		return nil, fmt.Errorf("grype scan: %w", err)
	}
	var doc Document
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, fmt.Errorf("grype scan: decode output: %w", err)
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
