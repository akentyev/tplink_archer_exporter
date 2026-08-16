# distroless/static: the binary is static, so the image carries no libc and no
# shell.
#
# The build stage pins the patch release go.mod asks for, and runs on the build
# machine's architecture, cross-compiling — which keeps buildx off QEMU.
FROM --platform=$BUILDPLATFORM golang:1.26.6-alpine AS build

# The official images already set this; stating it keeps the pin above true
# whatever the base decides later.
ENV GOTOOLCHAIN=local

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags='-s -w' -o /out/tplink_exporter ./cmd/tplink_exporter

FROM gcr.io/distroless/static-debian12:nonroot

ARG VERSION=dev
ARG REVISION=unknown
# ghcr links a package to its repository by image.source; without it the package
# is orphaned and has to be linked by hand. CI fills the other two from the tag
# and the commit.
LABEL org.opencontainers.image.source="https://github.com/akentyev/tplink_archer_exporter" \
      org.opencontainers.image.description="Prometheus exporter for the TP-Link Archer AX80" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

COPY --from=build /out/tplink_exporter /usr/local/bin/tplink_exporter
# uid 65532, shipped by the nonroot tag.
USER nonroot:nonroot
ENV TPLINK_LISTEN=:9110
EXPOSE 9110
ENTRYPOINT ["/usr/local/bin/tplink_exporter"]
