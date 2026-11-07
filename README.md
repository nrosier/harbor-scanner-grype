# harbor-scanner-grype

A [Harbor](https://goharbor.io) pluggable scanner adapter for standalone
[Grype](https://github.com/anchore/grype) — so Harbor can run Grype the way it runs Trivy:
register it under *Interrogation Services*, assign it to a project, and Harbor scans on push,
renders the report, enforces *prevent vulnerable images from running* and honours the CVE allowlist.

## Why this exists

Anchore's own [harbor-scanner-adapter](https://github.com/anchore/harbor-scanner-adapter) targets
Anchore Engine / Enterprise, not the open-source Grype binary. Engine is end-of-life, Enterprise is
commercial. If you already run Grype in CI and want the same findings inside Harbor, there was no
adapter for that.

This one has no dependency beyond the `grype` and `syft` executables and the Go standard library
(the Go code itself is standard library only): no Redis, no database, no web framework.

## How it works

```
Harbor ──POST /api/v1/scan─────▶ adapter ──grype registry:<ref> -o json──▶ registry
Harbor ◀─GET /api/v1/scan/{id}/report── adapter ◀──────── JSON ──────────┘
```

The adapter accepts a scan, runs `grype` against the registry reference Harbor supplied,
maps the result into Harbor's vulnerability report format and serves it under the scan id.
If the scan request enables the SBOM capability, it additionally runs `syft` to produce an SPDX
SBOM. The two jobs are independent: one failing does not fail the other.
Jobs live in memory with a TTL; a finished scan is a value, not a row in a database.

| Endpoint | Behaviour |
|---|---|
| `GET /api/v1/metadata` | capabilities (vulnerability and SBOM), Grype and DB version |
| `POST /api/v1/scan` | accepts the scan, returns `202` and a scan id |
| `GET /api/v1/scan/{id}/report` | vulnerability report: `302` while running, `200` with the report when done |
| `GET /api/v1/scan/{id}/report?sbom_media_type=application%2Fspdx%2Bjson` | SBOM report, requested with `Accept: application/vnd.security.sbom.report+json; version=1.0` |
| `GET /healthz` | liveness |

When SBOM is enabled both capabilities carry an explicit `type` (needed by Harbor 2.12+ to keep vulnerability scanning available); otherwise the vulnerability capability is untyped as before.

`POST /api/v1/scan` honours `enabled_capabilities` in the scan request. When it is absent or
empty the adapter runs a vulnerability scan only. A request may enable the vulnerability
capability, the SBOM capability, or both; each gets its own job under the same scan id.

**SBOM output is SPDX only** (`application/spdx+json`). Harbor itself only requests
`application/spdx+json`, so CycloneDX is not advertised in the metadata and is rejected.

The `sbom_media_type` value must be percent-encoded as Harbor sends it (`application%2Fspdx%2Bjson`). A literal `+` in a query string decodes as a space, so `application/spdx+json` written unencoded is rejected with `400`.

Status codes:

* `POST /api/v1/scan`: `202` accepted; `400` malformed JSON or a capability without
  `produces_mime_types`; `422` unsupported artifact MIME type, missing repository or digest,
  unsupported capability type, unsupported report MIME type, or a missing or unsupported SBOM
  media type; `413` request body over 1 MiB; `503` while the adapter is shutting down.
* `GET /api/v1/scan/{id}/report`: `200` report; `302` with `Location` and `Refresh-After`
  while the job is pending or running; `400` if an SBOM report is requested with a missing or
  unsupported `sbom_media_type`; `404` unknown scan id (or no job of the requested kind);
  `500` if the job failed; `501` (Harbor `ErrorResponse`) for an unsupported `Accept` header.
  Checks run in this order: `Accept`, `sbom_media_type`, job lookup, job status.

Reports are produced both as `application/vnd.security.vulnerability.report; version=1.1`
and the legacy `application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0`.

### Mapping decisions

* **Severity** maps Grype's scale onto Harbor's one-to-one (case-insensitive): `Critical`, `High`,
  `Medium`, `Low` and `Negligible` each keep their own level. Any other value becomes `Unknown`.
* **CVSS** reports the first v3.x entry and the first v2.x entry the record carries (in record order,
  not by score); a missing version is simply omitted.
* **Identifiers**: a GHSA-only finding is reported under its related CVE id when one exists
  (`SCANNER_PREFER_CVE`, default on), because Harbor's CVE allowlist matches on CVE ids.
* Duplicate matches for the same package and vulnerability are collapsed.

## Install

### Helm

```sh
helm install harbor-scanner-grype ./charts/harbor-scanner-grype \
  --namespace harbor \
  --set image.repository=<your-registry>/harbor-scanner-grype \
  --set image.tag=<tag>
```

### Container

```sh
docker build -t harbor-scanner-grype:dev .
docker run -p 8080:8080 harbor-scanner-grype:dev
```

Vulnerability scans need a Grype vulnerability database. The Helm chart provides it with an init
container that runs `grype db update` into the DB cache volume before the adapter starts. A bare
`docker run` has no such step: without a database present, vulnerability scans fail with HTTP 500
`grype scan failed` (SBOM generation does not need the database and still works). Populate it
yourself, for example by running `grype db update` inside the container, or by mounting a
pre-populated cache directory and pointing `GRYPE_DB_CACHE_DIR` at it. Setting
`SCANNER_GRYPE_DB_AUTO_UPDATE=true` only passes `GRYPE_DB_AUTO_UPDATE=true` to the grype child
process, which then refreshes the database itself on each scan (this needs network access to
Grype's database host).

The image ships the `grype` and `syft` binaries verbatim from the official Anchore images, so a
Grype upgrade is an image rebuild, nothing else. Syft is pinned to v1.44.0, the version Grype
v0.112.0 is built against; bump the two together.

## Register it in Harbor

*Administration → Interrogation Services → Scanners → NEW SCANNER*

| Field | Value |
|---|---|
| Endpoint | `http://harbor-scanner-grype.harbor.svc:8080` |
| Auth | None |
| **Use internal registry address** | **checked** |

**The internal-address checkbox is not optional.** With the external address Harbor hands the
adapter a token realm pointing at the registry's public host. Grype's registry client refuses a
realm whose host is a private or link-local address (an SSRF guard), and every scan fails with
`invalid realm in www-authenticate`. With the box checked Harbor passes `http://harbor-core:80`,
whose realm resolves inside the cluster. Harbor's built-in Trivy is configured the same way.
That is also why the chart defaults to `config.registryUseHTTP: true`.

**Minimum Harbor version for the SBOM capability: 2.11 or newer** (per Harbor's source; not tested against a live Harbor). Harbor 2.10's metadata validation only accepts vulnerability report MIME types in `produces_mime_types`, so advertising the SBOM report MIME makes registration fail on 2.10 and older; SBOM support was added in v2.11.0.

Note that Harbor keeps **one active scanner per project**. Assign Grype to a project to use it
there; a second opinion alongside Trivy on the same artifact is not something Harbor supports today
([goharbor/harbor#9687](https://github.com/goharbor/harbor/issues/9687)).

## Configuration

Everything is an environment variable.

| Variable | Default | Meaning |
|---|---|---|
| `SCANNER_API_ADDR` | `:8080` | listen address |
| `SCANNER_GRYPE_PATH` | `grype` | path to the grype binary |
| `SCANNER_SYFT_PATH` | `syft` | path to the syft binary (the image sets `/usr/bin/syft`) |
| `SCANNER_SCAN_TIMEOUT` | `5m` | per-scan timeout |
| `SCANNER_JOB_TTL` | `1h` | finished jobs are dropped after this (`0` = never) |
| `SCANNER_CLEANUP_INTERVAL` | `5m` | cleanup tick |
| `SCANNER_REGISTRY_INSECURE_SKIP_TLS` | `false` | skip TLS verification towards the registry |
| `SCANNER_REGISTRY_USE_HTTP` | `false` | plain HTTP registry |
| `SCANNER_GRYPE_DB_AUTO_UPDATE` | `false` | let grype refresh its DB per scan |
| `SCANNER_PREFER_CVE` | `true` | report GHSA-only findings under their related CVE id |
| `SCANNER_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `SCANNER_WORKER_CONCURRENCY` | `2` | max concurrent Grype/Syft subprocesses (integer >= 1), counting Grype and Syft jobs separately; one scan request can use two (vulnerability + SBOM). Extra jobs wait as Pending. Size container memory for this many scans (Grype with its DB commonly needs 1-2 GiB each) |

Registry credentials arrive per request from Harbor and are passed to the `grype` and `syft` child processes
through its environment only. They are never written to disk or logged.

## Development

```sh
make test        # go test ./...
make vet
make build
make lint-chart
```

The tests need no network access: the Grype and Syft output is exercised against checked-in
fixtures. GitHub Actions CI runs `go vet`, `go test`, `go build` and `make lint-chart` on pull
requests and pushes to `main`.

## Status

Working and tested against Harbor 2.15 with Grype 0.112. First live scan: the adapter scanning
its own image, 115 findings, 8 critical, about 40 seconds including database load.

The SBOM capability requires Harbor 2.11 or newer (per Harbor's source; not tested against a live Harbor).

Covered: vulnerability scans, and SPDX SBOM generation via Syft (`application/spdx+json`).
CycloneDX is not produced because Harbor does not consume it.

Not yet covered: SBOM ingestion (Harbor can hand over an SBOM instead of a reference),
horizontal scaling (the job store is in-memory, so run one replica), and a Grype DB volume
shared between restarts.

## Provenance

Architecture, tests and reviews are human-directed; the implementation of each package was written
by a local LLM against failing tests and reviewed before it was kept. Four real defects were caught
in review, among them an OR-instead-of-AND in the CVSS version switch that the fixture happened not
to expose.

## License

Apache License 2.0, see [LICENSE](LICENSE).
