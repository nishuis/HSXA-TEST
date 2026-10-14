# syntax=docker/dockerfile:1
# Build stage: static binary, no CGO, version injected at link time.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=0.1.0
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
        -ldflags "-s -w \
          -X hsxa-banner-fingerprint/internal/version.Version=${VERSION} \
          -X hsxa-banner-fingerprint/internal/version.GitCommit=${COMMIT} \
          -X hsxa-banner-fingerprint/internal/version.BuildDate=${BUILD_DATE}" \
        -o /out/bfp-server ./cmd/bfp-server

# Runtime stage: alpine, non root, healthcheck served by the binary itself so
# that no wget or curl is needed (plan.md §5.1).
FROM alpine:3.20 AS runtime
RUN adduser -D -H -u 10001 bfp && mkdir -p /rules && chown -R bfp:bfp /rules
COPY --from=build /out/bfp-server /usr/local/bin/bfp-server
USER bfp
EXPOSE 8080
ENV BFP_LISTEN_ADDR=:8080 \
    BFP_LOG_LEVEL=info \
    BFP_RULES_DIR=/rules
HEALTHCHECK --interval=10s --timeout=3s --start-period=3s --retries=3 \
    CMD ["bfp-server", "-health-check"]
ENTRYPOINT ["/usr/local/bin/bfp-server"]
CMD []
