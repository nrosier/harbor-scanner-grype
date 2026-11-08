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
| SBOMs via Syft CLI (`syft registry:<ref> -o spdx-json`), SPDX only | Harbor only requests `application/spdx+json`; CycloneDX is not advertised. Syft is pinned to the version Grype is built against (Grype v0.121.2 / Syft v1.57.0) |
| In-memory job store, exactly one replica | Harbor polls the same adapter URL; a Redis store can be added behind `job.Store` later, the API does not change |
| Registry credentials passed to grype via environment variables, never on argv | argv is visible in `ps`; env of a child process is not |
| Prefer CVE identifiers over GHSA in reports | Harbor's CVE allowlist (the exception mechanism) matches on ID; a GHSA-only finding could not be waived |
| Grype DB refreshed by the container start / a sidecar cron, not per scan | scan latency and registry-rate predictability; `SCANNER_GRYPE_DB_AUTO_UPDATE=true` opts back in |

## Packages

```
cmd/adapter        main: config -> store -> runner -> api -> http.Server (graceful shutdown)
internal/config    env parsing, strict (invalid value = startup error)
pkg/harbor         Harbor Adapter API wire types and MIME constants (no logic)
pkg/grype          Grype JSON model, CLI runner (Execer abstraction), Mapper to Harbor report;
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

* runs as non-root, read-only root filesystem, Grype DB on an emptyDir
* no credentials on argv, no credentials in logs (the runner logs the
  image ref only)
* request bodies limited to 1 MiB; scan timeout bounded
* the adapter has no auth of its own: deploy it cluster-internal and
  register the internal Service URL in Harbor

## Deployment

Helm chart `charts/harbor-scanner-grype`: Deployment (1 replica,
enforced), Service :8080, ServiceAccount, probes on `/healthz`, env from
`values.config`. Image: multi-stage Dockerfile, runtime = distroless +
`grype` and `syft` binaries copied from `anchore/grype:<version>` and
`anchore/syft:<version>` (Syft pinned to the version Grype is built
against; `SCANNER_SYFT_PATH` points at `/usr/bin/syft`). The Grype DB is
fetched at container start (`grype db update`) via an init step, so the
first scan does not pay for it.

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
