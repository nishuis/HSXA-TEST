# syntax=docker/dockerfile:1
# The CLI ships as its own one-shot image: docker compose run --rm cli ...
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
        -o /out/bfp-cli ./cmd/bfp-cli

FROM alpine:3.20 AS runtime
RUN adduser -D -H -u 10002 bfp
COPY --from=build /out/bfp-cli /usr/local/bin/bfp-cli
USER bfp
ENV BFP_SERVER=http://server:8080
WORKDIR /data
ENTRYPOINT ["/usr/local/bin/bfp-cli"]
CMD ["version"]
