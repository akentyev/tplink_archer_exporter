# --platform keeps the build stage on the runner's architecture and cross-compiles
# from there, which keeps buildx off QEMU. CGO_ENABLED=0 below is what makes the
# result run on distroless/static, which carries no libc.
FROM --platform=$BUILDPLATFORM golang:1.26.6-alpine AS build

# Set by the official images already; stated so the pin above survives a base
# that stops setting it.
ENV GOTOOLCHAIN=local

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

ARG TARGETOS
ARG TARGETARCH
# Declared again here because ARG is per-stage: the pair in the final stage
# reaches the labels and not the compiler.
ARG VERSION=dev
ARG REVISION=unknown
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath \
      -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" \
      -o /out/tplink_exporter ./cmd/tplink_exporter

FROM gcr.io/distroless/static-debian12:nonroot

ARG VERSION=dev
ARG REVISION=unknown
# ghcr links a package to its repository by image.source; without it the package
# is orphaned. The defaults are repeated in the expansion because an empty
# --build-arg overrides an ARG default.
LABEL org.opencontainers.image.source="https://github.com/akentyev/tplink_archer_exporter" \
      org.opencontainers.image.description="Prometheus exporter for the TP-Link Archer AX80" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION:-dev}" \
      org.opencontainers.image.revision="${REVISION:-unknown}"

COPY --from=build /out/tplink_exporter /usr/local/bin/tplink_exporter
# uid 65532, shipped by the nonroot tag.
USER nonroot:nonroot
ENV TPLINK_LISTEN=:9110
EXPOSE 9110
ENTRYPOINT ["/usr/local/bin/tplink_exporter"]
