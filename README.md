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

This one has no dependency beyond the `grype` executable and the Go standard library: no Redis,
no database, no web framework.

## How it works

```
Harbor ──POST /api/v1/scan─────▶ adapter ──grype registry:<ref> -o json──▶ registry
Harbor ◀─GET /api/v1/scan/{id}/report── adapter ◀──────── JSON ──────────┘
```

The adapter accepts a scan, runs `grype` against the registry reference Harbor supplied,
maps the result into Harbor's vulnerability report format and serves it under the job id.
Jobs live in memory with a TTL; a finished scan is a value, not a row in a database.

| Endpoint | Behaviour |
|---|---|
| `GET /api/v1/metadata` | capabilities, Grype and DB version |
| `POST /api/v1/scan` | accepts the scan, returns `202` and a job id |
| `GET /api/v1/scan/{id}/report` | `302` while running, `200` with the report when done |
| `GET /healthz` | liveness |

Reports are produced both as `application/vnd.security.vulnerability.report; version=1.1`
and the legacy `application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0`.

### Mapping decisions

* **Severity** maps Grype's scale onto Harbor's, with `Negligible` folded into `Low`.
* **CVSS** prefers a v3.x vector when the record carries several; the highest base score wins.
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

The image ships the `grype` binary verbatim from the official Anchore image, so a Grype upgrade
is an image rebuild, nothing else.

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

Note that Harbor keeps **one active scanner per project**. Assign Grype to a project to use it
there; a second opinion alongside Trivy on the same artifact is not something Harbor supports today
([goharbor/harbor#9687](https://github.com/goharbor/harbor/issues/9687)).

## Configuration

Everything is an environment variable.

| Variable | Default | Meaning |
|---|---|---|
| `SCANNER_API_ADDR` | `:8080` | listen address |
| `SCANNER_GRYPE_PATH` | `grype` | path to the grype binary |
| `SCANNER_SCAN_TIMEOUT` | `5m` | per-scan timeout |
| `SCANNER_JOB_TTL` | `1h` | finished jobs are dropped after this (`0` = never) |
| `SCANNER_CLEANUP_INTERVAL` | `5m` | cleanup tick |
| `SCANNER_REGISTRY_INSECURE_SKIP_TLS` | `false` | skip TLS verification towards the registry |
| `SCANNER_REGISTRY_USE_HTTP` | `false` | plain HTTP registry |
| `SCANNER_GRYPE_DB_AUTO_UPDATE` | `false` | let grype refresh its DB per scan |
| `SCANNER_PREFER_CVE` | `true` | report GHSA-only findings under their related CVE id |
| `SCANNER_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |

Registry credentials arrive per request from Harbor and are passed to the `grype` child process
through its environment only. They are never written to disk or logged.

## Development

```sh
make test        # go test ./...
make vet
make build
make lint-chart
```

39 tests, standard library only, no network access required — the Grype output is exercised
against a checked-in fixture.

## Status

Working and tested against Harbor 2.15 with Grype 0.112. First live scan: the adapter scanning
its own image, 115 findings, 8 critical, about 40 seconds including database load.

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
