# Architecture

## Goal

Make Grype a first-class Harbor scanner so that Harbor is the single
place for scan results, pull blocking and CVE exceptions. The adapter
must be small enough to be maintained by one person and to survive Grype
and Harbor upgrades without code changes.

## Constraints and decisions

| Decision | Rationale |
|---|---|
| Go code is standard library only (`net/http`, `os/exec`, `encoding/json`, `log/slog`); the image bundles two external binaries, `grype` and `syft` | no Go dependency churn, fast builds, easy audit |
| Grype via CLI (`grype registry:<ref> -o json`), not as a Go library | Grype's library API is not stable; the CLI JSON schema is versioned and documented; Grype upgrades = image rebuild |
| SBOMs via Syft CLI (`syft registry:<ref> -o spdx-json`), SPDX only | Harbor only requests `application/spdx+json`; CycloneDX is not advertised. Syft is pinned to the version Grype is built against (Grype v0.112.0 / Syft v1.44.0) |
| In-memory job store, exactly one replica | Harbor polls the same adapter URL; a Redis store can be added behind `job.Store` later, the API does not change |
| Registry credentials passed to grype via environment variables, never on argv | argv is visible in `ps`; env of a child process is not |
| Prefer CVE identifiers over GHSA in reports | Harbor's CVE allowlist (the exception mechanism) matches on ID; a GHSA-only finding could not be waived |
| Grype DB managed by the adapter (`grype db update` at start, then every `SCANNER_DB_UPDATE_INTERVAL`), not per scan | the image alone must work in docker-compose; scan latency stays predictable; `SCANNER_GRYPE_DB_AUTO_UPDATE=true` still opts into Grype's own per-scan check but is not needed (see "Vulnerability database lifecycle") |

## Packages

```
cmd/adapter        main: config -> store -> runner -> api -> http.Server (graceful shutdown)
internal/config    env parsing, strict (invalid value = startup error)
pkg/harbor         Harbor Adapter API wire types and MIME constants (no logic)
pkg/grype          Grype JSON model, CLI runner (Execer abstraction), Mapper to Harbor report;
                   dbupdate.go: DBUpdater (startup + periodic `grype db update`, backoff, scan gate), DBState;
                   syft.go: SBOMGenerator interface + SyftRunner (SPDX JSON via the syft CLI)
pkg/job            Store interface + MemoryStore (mutex, map, injectable clock, TTL cleanup);
                   a scan id owns a set of jobs addressed by Key{ID, Kind, SBOMMediaType}
pkg/api            http.Handler: routes, validation, Accept negotiation, async scan start,
                   worker semaphore, graceful Shutdown
```

Dependency direction: `api -> job, grype, harbor`; `grype -> harbor`;
`job -> harbor`; nothing imports `api`.

## Request lifecycle

1. `POST /api/v1/scan` validates JSON, artifact MIME type and
   `enabled_capabilities` (absent/empty = vulnerability only). It creates
   one job set under a single scan id: one vulnerability job and one SBOM
   job per requested SBOM media type, keyed by kind + SBOM media type.
   Each job is a Pending job with its own goroutine; the answer is 202
   `{id}`. While shutting down it answers 503.
2. Each job goroutine first acquires a slot of the worker semaphore
   (`SCANNER_WORKER_CONCURRENCY`, counting Grype and Syft jobs separately;
   the job stays Pending while waiting), then runs:
   * vulnerability: `SetJobRunning`; `runner.Scan(ctx)`;
     `mapper.Map(doc, artifact)`; `SetJobReport` or `SetJobError`.
   * SBOM: `SetJobRunning`; `syft` generates SPDX JSON; the raw document
     is wrapped in the SBOM report envelope; `SetJobSBOM` or `SetJobError`.

   Panics are recovered and stored as errors. The jobs of one scan are
   independent: a failing SBOM job does not fail the vulnerability job and
   vice versa.
3. `GET /api/v1/scan/{id}/report` checks, in order: `Accept` (unsupported
   -> 501), `sbom_media_type` for the SBOM report type (missing or
   unsupported -> 400), job lookup by key (unknown -> 404), job status.
   Pending/Running -> 302 with `Location` and `Refresh-After: 15`;
   Finished -> 200 with the report in the negotiated MIME type; Failed ->
   500 error envelope.
4. A ticker calls `store.Cleanup(JobTTL)` every `CleanupInterval`.
5. Graceful shutdown: the server stops accepting scans (503), waits for
   queued and running jobs until the shutdown context expires, then
   cancels the scan contexts, allows a short grace period to unwind, and
   marks every job still Pending/Running as Failed with "interrupted by
   shutdown".

## Vulnerability database lifecycle

Findings from Grype v0.112.0's source (`grype/db/v6/installation/curator.go`, tag v0.112.0) and from
running the published image:

* **`grype db update` is not atomic and takes no lock.** `Update()` -> `update()` downloads and
  unpacks into a temp directory `<cache>/grype-db-download*` (`distribution/client.go` `Download`),
  hydrates it, then `activate()` -> `replaceDB()` does `RemoveAll(<cache>/6)` on the live directory
  *and then* `Rename(tmp, <cache>/6)` (curator.go `replaceDB`, "remove any previous databases").
  Between the two calls there is no database; a killed process leaves the download directory
  behind. A grep for flock/lock files in the grype tree finds none used for the DB. Readers open the
  file with `immutable=1&mode=ro` (`grype/db/internal/gormadapter/open.go`), i.e. SQLite is told the
  file never changes, so a scan reading while the file is deleted/replaced can see errors or
  inconsistent pages. There is no safe concurrent mode; the adapter serialises (below).
* **Environment variables** (from `grype config` of the v0.112.0 binary and `options/database.go`):
  `GRYPE_DB_CACHE_DIR`, `GRYPE_DB_UPDATE_URL` (default `https://grype.anchore.io/databases`),
  `GRYPE_DB_AUTO_UPDATE` (default `true` in grype; the adapter always passes an explicit value to
  scans), `GRYPE_DB_VALIDATE_AGE` (default `true`), `GRYPE_DB_MAX_ALLOWED_BUILT_AGE` (default
  `120h`), `GRYPE_DB_REQUIRE_UPDATE_CHECK` (default `false`, but `grype db update` forces it to
  `true`), `GRYPE_DB_VALIDATE_BY_HASH_ON_START` (default `true`),
  `GRYPE_DB_UPDATE_AVAILABLE_TIMEOUT` (30s), `GRYPE_DB_UPDATE_DOWNLOAD_TIMEOUT` (5m),
  `GRYPE_DB_MAX_UPDATE_CHECK_FREQUENCY` (2h; disabled for `db` subcommands).
* **Cheap availability check: `grype db status -o json`.** Output
  `{"schemaVersion","from","built","path","valid":true}`, exit 0 with a usable DB; with none:
  `{"schemaVersion":"","path":".../6/vulnerability.db","valid":false,"error":"database does not exist"}`
  and exit 1 (observed with the published image). It also reports a DB older than
  `GRYPE_DB_MAX_ALLOWED_BUILT_AGE` or with a bad checksum as invalid. By default it hashes the whole
  DB file (about 3.4 GB on disk; several seconds), so the adapter sets
  `GRYPE_DB_VALIDATE_BY_HASH_ON_START=false` for its status calls; scans still validate on load.
  `grype version -o json` has **no DB section** in v0.112.0 (`supportedDbSchema` only), so the
  adapter's old `db.built` parse always yielded the zero time; the DB build time for `/metadata` now
  comes from `db status`.
* **Default location without `GRYPE_DB_CACHE_DIR`:** `xdg.CacheHome/grype/db` (`installation.DefaultConfig`),
  and for the distroless image (user `nonroot`, UID 65532, `HOME=/home/nonroot`, no volume) that is
  `/home/nonroot/.cache/grype/db`, observed in `db status`. It lives in the container's writable
  layer, so it is gone whenever the container is recreated, and nothing in the image or in compose
  ever populated it. That is why the compose deployment in issue #6 never had a DB.

Design:

* `DBUpdater` (`pkg/grype/dbupdate.go`) runs in the background from `main`: it first reads
  `db status` (so an installed DB makes the adapter ready immediately), then runs `grype db update`
  under a 10 minute per-run timeout, then re-reads `db status`, and repeats every
  `SCANNER_DB_UPDATE_INTERVAL`. Failures are logged at WARN with the full error and retried with
  capped exponential backoff (1m doubling to 1h, never beyond the interval); the installed DB is
  kept. Interval `0` runs only the startup update (retried until it succeeds). Clock, executor and
  state are injectable; the tests use no real sleeps. At startup it also removes
  `grype-db-download*` directories left by an interrupted update.
* **Serialisation with scans uses a gate (reader/writer lock), because Grype is not safe against
  concurrent readers.** Scans (`DBUpdater.Guard` wraps the runner) take the shared side for their
  whole run; an update takes the exclusive side. A waiting update blocks new scans so it cannot be
  starved. It is a small context-aware lock instead of `sync.RWMutex`, since a scan queued behind a
  long download must remain cancellable on shutdown. Cost: scans queue while a DB switch runs
  (the check is seconds; a real download is about 1.5 minutes). Scans already running are never
  broken, and a blocked job still counts against `SCANNER_WORKER_CONCURRENCY`.
* **Availability state** (`DBState`, atomic) is true after a successful `db status`: at startup
  when a DB exists, or after an update. A failed update never clears it if `db status` still says
  the DB is usable.
* **Readiness:** `GET /readyz` is 503 (`ErrorResponse`) until the state is ready, and also 503 once
  `Shutdown` has begun, so Kubernetes/compose stop routing during the drain, while `GET /healthz`
  (liveness) stays 200 in both cases. `/adapter healthcheck` is the same probe for container
  runtimes without curl.
* **Fail fast:** before calling the runner, a vulnerability job checks the state; with no DB it
  fails at once with `vulnerability database not available`, before the image is pulled. The
  public message is fixed (no stderr, paths or credentials); the Grype `failed to load
  vulnerability db` stderr is mapped to the same message, with the full error logged. SBOM jobs do
  not check the DB.
* **Metadata:** after each successful update the `DBTimeCache` is primed with the new build time.
* **Shutdown order:** on SIGTERM the updater is cancelled first (killing a running
  `grype db update` and releasing the gate so queued scans can drain), then scans drain, then the
  HTTP listener stops.

Operations: the image sets `GRYPE_DB_CACHE_DIR=/var/lib/grype/db`, created in the build stage and
owned by 65532:65532; mount a named volume there (compose example in `examples/docker-compose`).
The Helm chart overrides it with its emptyDir and keeps the init container so the pod is ready
without waiting for the adapter's download; its readiness probe is `/readyz`, liveness `/healthz`.
Harbor itself only calls `/api/v1/metadata` and does not look at `/readyz`.

## Mapping (Grype match → Harbor VulnerabilityItem)

| Harbor field | Source |
|---|---|
| `id` | `vulnerability.id`; if not `CVE-*` and `PreferCVE`, first `relatedVulnerabilities[].id` that starts with `CVE-` (original kept in `vendor_attributes.grype_id`) |
| `package`, `version` | `artifact.name`, `artifact.version` |
| `fix_version` | `vulnerability.fix.versions[0]` or empty |
| `severity` | `vulnerability.severity`, case-insensitive, 1:1 to Harbor's Critical/High/Medium/Low/Negligible/Unknown |
| `description` | `vulnerability.description` |
| `links` | `dataSource`, then `urls`, then related vulnerabilities' `dataSource`+`urls`; deduplicated, order kept |
| `layer.digest` | `artifact.locations[0].layerID` |
| `preferred_cvss` | first `cvss[]` with version `3.*` → `score_v3`/`vector_v3`; first with `2.*` → `score_v2`/`vector_v2`; omitted if none |
| `cwe_ids` | `cwes[].id` |
| `vendor_attributes` | `purl`, `namespace`, `matcher` (first matchDetails), `fix_state`, `grype_id` |

Items with equal `(id, package, version)` are merged: links unioned,
first layer wins. Items are sorted by severity desc, id asc, package
asc. Report severity = max item severity, `Unknown` for an empty report.

## Metadata

```
scanner:      {name: Grype, vendor: Anchore, version: <grype version>}
capabilities: 1. vulnerability ("type": "vulnerability" when SBOM is on; omitted when SBOM is off): consumes [oci manifest, docker v2] -> produces [security report v1.1, legacy harbor+json v1.0]
              2. sbom:          consumes [oci manifest, docker v2] -> produces [sbom report v1.0],
                                additional attribute sbom_media_types = [application/spdx+json]
properties:   harbor.scanner-adapter/scanner-type = os-package-vulnerability
              harbor.scanner-adapter/vulnerability-database-updated-at = <db built, RFC3339>
              harbor.scanner-adapter/registry-authorization-type = Bearer
```

`registry-authorization-type = Bearer` makes Harbor send a robot-account
Bearer token; the runner also accepts Basic for manual testing.

## Security

* runs as non-root, read-only root filesystem in Kubernetes, Grype DB on an emptyDir (a volume in compose)
* no credentials on argv, no credentials in logs (the runner logs the
  image ref only)
* request bodies limited to 1 MiB; scan timeout bounded
* the adapter has no auth of its own: deploy it cluster-internal and
  register the internal Service URL in Harbor

## Deployment

Helm chart `charts/harbor-scanner-grype`: Deployment (1 replica,
enforced), Service :8080, ServiceAccount, liveness probe on `/healthz`, readiness probe on `/readyz`, env from
`values.config`. Image: multi-stage Dockerfile, runtime = distroless +
`grype` and `syft` binaries copied from `anchore/grype:<version>` and
`anchore/syft:<version>` (Syft pinned to the version Grype is built
against; `SCANNER_SYFT_PATH` points at `/usr/bin/syft`). The Grype DB is
fetched by the adapter itself (see "Vulnerability database lifecycle"); the
chart's init container only seeds it before the adapter starts.

## Registration in Harbor (verified 2026-09-07)

Register the adapter with **"Use internal registry address"** enabled
(`use_internal_addr: true`), exactly like the built-in Trivy scanner.
Harbor then hands the adapter `registry.url = http://harbor-core:80`, whose
token realm is `http://harbor-core:80/service/token`. With the external
address Harbor answers with `realm="https://<external-ip>/service/token"`
and Grype 0.112 refuses it: `invalid realm in www-authenticate: realm host
"<registry-ip>" is a private or link-local address` (SSRF guard in the
registry client). Consequently the chart runs with
`config.registryUseHTTP: true` (plain HTTP to harbor-core inside the
cluster) and `registryInsecureSkipTLS` stays false.

The SBOM capability needs Harbor 2.11 or newer (per Harbor's source; not tested against a live Harbor): 2.10's metadata validation only accepts vulnerability report MIME types in `produces_mime_types`, so registration fails there. When sending `sbom_media_type` in a query string, percent-encode it (`application%2Fspdx%2Bjson`); a literal `+` decodes as a space.

First live scan (adapter image scanning itself, in-cluster pod, DB
downloaded on demand): 115 findings, 8 Critical, report delivered in
about 40 s including the DB download.

## Out of scope (for now)

* CycloneDX SBOM output (Harbor only requests SPDX)
* SBOM ingestion (scanning a Harbor SBOM accessory for vulnerabilities
  instead of the image)
* Redis job store / horizontal scaling
* Harbor-side "n scanners per artifact" (separate project)
