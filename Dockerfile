# syntax=docker/dockerfile:1.7

ARG GO_VERSION=1.26.3
ARG ALPINE_VERSION=3.23

FROM golang:${GO_VERSION}-alpine AS base

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

FROM base AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/zitadeltg ./cmd/zitadeltg

FROM alpine:${ALPINE_VERSION} AS runtime

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S zitadeltg \
    && adduser -S -D -H -G zitadeltg zitadeltg \
    && mkdir -p /data /config \
    && chown -R zitadeltg:zitadeltg /data /config

COPY --from=build /out/zitadeltg /usr/local/bin/zitadeltg
COPY --chown=zitadeltg:zitadeltg config.example.yaml /data/config.example.yaml

WORKDIR /data
USER zitadeltg

EXPOSE 8080
VOLUME ["/data"]

ENTRYPOINT ["zitadeltg"]
CMD ["-config", "/data/config.yaml"]
