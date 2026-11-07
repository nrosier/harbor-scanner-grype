# syntax=docker/dockerfile:1

# Stage 1: build the adapter. Standard-library-only, so there is no
# go.sum to vendor; CGO_ENABLED=0 produces a static binary.
FROM golang:1.24 AS builder
# TARGETOS/TARGETARCH are supplied by BuildKit; default to the classic
# builder's linux/amd64 when they are not.
ARG TARGETOS=linux
ARG TARGETARCH=amd64
WORKDIR /src
COPY go.mod ./
COPY cmd/ cmd/
COPY internal/ internal/
COPY pkg/ pkg/
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/adapter ./cmd/adapter

# Stage 2: minimal runtime. The grype and syft binaries ship verbatim from
# the official Anchore images so upgrades are image rebuilds only. Syft is
# pinned to the version Grype is built against (v0.112.0 links Syft v1.44.0).
FROM gcr.io/distroless/static
# the official images keep the binaries at /grype and /syft
COPY --from=anchore/grype:v0.112.0 /grype /usr/bin/grype
COPY --from=anchore/syft:v1.44.0 /syft /usr/bin/syft
COPY --from=builder /out/adapter /adapter
ENV SCANNER_GRYPE_PATH=/usr/bin/grype
ENV SCANNER_SYFT_PATH=/usr/bin/syft
USER 65532
ENTRYPOINT ["/adapter"]
