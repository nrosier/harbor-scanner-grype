package grype

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/TechPrototyper/harbor-scanner-grype/pkg/harbor"
)

// MaxSBOMBytes bounds the SPDX document accepted from Syft. This is a chosen
// bound, not a measured one (real Syft SPDX sizes are unverified). The default
// OSExecer enforces it while reading stdout, killing syft when exceeded; the
// post-hoc length check below covers other Execer implementations.
const MaxSBOMBytes = 128 << 20

// Environment variable names understood by syft.
const (
	SyftEnvAuthAuthority   = "SYFT_REGISTRY_AUTH_AUTHORITY"
	SyftEnvAuthUsername    = "SYFT_REGISTRY_AUTH_USERNAME"
	SyftEnvAuthPassword    = "SYFT_REGISTRY_AUTH_PASSWORD"
	SyftEnvAuthToken       = "SYFT_REGISTRY_AUTH_TOKEN"
	SyftEnvInsecureSkipTLS = "SYFT_REGISTRY_INSECURE_SKIP_TLS_VERIFY"
	SyftEnvInsecureHTTP    = "SYFT_REGISTRY_INSECURE_USE_HTTP"
	SyftEnvCheckAppUpdate  = "SYFT_CHECK_FOR_APP_UPDATE"
)

// SBOMGenerator produces an SPDX JSON document for an artifact.
type SBOMGenerator interface {
	// GenerateSPDX returns the untouched SPDX 2.x JSON document.
	GenerateSPDX(ctx context.Context, req harbor.ScanRequest) (json.RawMessage, error)
}

// SyftOptions configure the Syft runner.
type SyftOptions struct {
	Path            string        // syft binary, default "syft"
	Timeout         time.Duration // per run, default 5m
	InsecureSkipTLS bool          // SYFT_REGISTRY_INSECURE_SKIP_TLS_VERIFY
	UseHTTP         bool          // SYFT_REGISTRY_INSECURE_USE_HTTP
}

// SyftRunner shells out to the syft binary.
type SyftRunner struct {
	Opts SyftOptions
	Exec Execer
}

var _ SBOMGenerator = (*SyftRunner)(nil)

// NewSyftRunner applies defaults (Path "syft", Timeout 5m, OSExecer).
func NewSyftRunner(opts SyftOptions) *SyftRunner {
	if opts.Path == "" {
		opts.Path = "syft"
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Minute
	}
	return &SyftRunner{Opts: opts, Exec: OSExecer{MaxStdoutBytes: MaxSBOMBytes}}
}

// BuildSyftCommand turns a scan request into syft argv + env:
//
//	args: registry:<ImageRef> -o spdx-json -q
//	env:  SYFT_REGISTRY_AUTH_AUTHORITY=<host>
//	      Basic -> SYFT_REGISTRY_AUTH_USERNAME/PASSWORD, Bearer -> SYFT_REGISTRY_AUTH_TOKEN
//	      SYFT_CHECK_FOR_APP_UPDATE=false
//	      SYFT_REGISTRY_INSECURE_SKIP_TLS_VERIFY / _USE_HTTP =true per options
//
// Credentials only ever appear in env. Empty Authorization is anonymous.
func (r *SyftRunner) BuildSyftCommand(req harbor.ScanRequest) (Command, error) {
	host, ref, err := registryParts(req)
	if err != nil {
		return Command{}, err
	}
	cmd := Command{Args: []string{"registry:" + ref, "-o", "spdx-json", "-q"}}
	env := []string{
		SyftEnvAuthAuthority + "=" + host,
		SyftEnvCheckAppUpdate + "=false",
	}
	switch scheme, credential := splitAuth(req.Registry.Authorization); strings.ToLower(scheme) {
	case "": // anonymous pull
	case "basic":
		userPass, err := base64.StdEncoding.DecodeString(credential)
		if err != nil {
			return Command{}, errors.New("scan request: invalid Basic credential encoding")
		}
		user, pass, ok := strings.Cut(string(userPass), ":")
		if !ok {
			return Command{}, errors.New("scan request: Basic credential must be <user>:<password>")
		}
		env = append(env, SyftEnvAuthUsername+"="+user, SyftEnvAuthPassword+"="+pass)
	case "bearer":
		env = append(env, SyftEnvAuthToken+"="+credential)
	default:
		// Never echo the value: without a space the "scheme" is the whole
		// Authorization header, i.e. possibly a bare credential, and this
		// error reaches logs and Harbor's 500 body.
		return Command{}, errors.New("scan request: unsupported authorization scheme")
	}
	if r.Opts.InsecureSkipTLS {
		env = append(env, SyftEnvInsecureSkipTLS+"=true")
	}
	if r.Opts.UseHTTP {
		env = append(env, SyftEnvInsecureHTTP+"=true")
	}
	cmd.Env = env
	return cmd, nil
}

// GenerateSPDX runs syft with a timeout (Opts.Timeout), validates the SPDX
// header fields and returns the stdout bytes unmodified.
func (r *SyftRunner) GenerateSPDX(ctx context.Context, req harbor.ScanRequest) (json.RawMessage, error) {
	cmd, err := r.BuildSyftCommand(req)
	if err != nil {
		return nil, err
	}
	runCtx := ctx
	if r.Opts.Timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, r.Opts.Timeout)
		defer cancel()
	}
	out, err := r.Exec.Run(runCtx, r.Opts.Path, cmd.Args, cmd.Env)
	if err != nil {
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			return nil, &Failure{
				Public: fmt.Sprintf("syft sbom generation failed: timed out after %s", r.Opts.Timeout),
				Err:    fmt.Errorf("syft sbom: timed out after %s: %w", r.Opts.Timeout, err),
			}
		}
		return nil, publicFailure(runCtx, "syft sbom generation failed", r.Opts.Timeout, fmt.Errorf("syft sbom: %w", err))
	}
	if len(out) > MaxSBOMBytes {
		return nil, &Failure{
			Public: "syft sbom generation failed: output exceeds limit",
			Err:    fmt.Errorf("syft sbom: output exceeds %d bytes: %w", MaxSBOMBytes, ErrOutputLimit),
		}
	}
	if err := validateSPDX(out); err != nil {
		return nil, &Failure{Public: "syft sbom generation failed: invalid SPDX output", Err: fmt.Errorf("syft sbom: %w", err)}
	}
	return json.RawMessage(out), nil
}

// validateSPDX checks the minimal SPDX 2.x document header. Errors name
// only what is missing, never the document content.
func validateSPDX(doc []byte) error {
	var hdr struct {
		SPDXVersion       string `json:"spdxVersion"`
		SPDXID            string `json:"SPDXID"`
		Name              string `json:"name"`
		DocumentNamespace string `json:"documentNamespace"`
	}
	if err := json.Unmarshal(doc, &hdr); err != nil {
		return errors.New("output is not a valid JSON object")
	}
	var missing []string
	if !strings.HasPrefix(hdr.SPDXVersion, "SPDX-2.") {
		missing = append(missing, "spdxVersion (want SPDX-2.x)")
	}
	if hdr.SPDXID != "SPDXRef-DOCUMENT" {
		missing = append(missing, "SPDXID (want SPDXRef-DOCUMENT)")
	}
	if hdr.Name == "" {
		missing = append(missing, "name")
	}
	if hdr.DocumentNamespace == "" {
		missing = append(missing, "documentNamespace")
	}
	if len(missing) > 0 {
		return fmt.Errorf("invalid SPDX document: missing or invalid %s", strings.Join(missing, ", "))
	}
	return nil
}
