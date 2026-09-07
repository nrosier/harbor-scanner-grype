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

# Stage 2: minimal runtime. The grype binary ships verbatim from the
# official Anchore image so Grype upgrades are image rebuilds only.
FROM gcr.io/distroless/static
# the official image keeps the binary at /grype (ENTRYPOINT ["/grype"])
COPY --from=anchore/grype:v0.112.0 /grype /usr/bin/grype
COPY --from=builder /out/adapter /adapter
ENV SCANNER_GRYPE_PATH=/usr/bin/grype
USER 65532
ENTRYPOINT ["/adapter"]
