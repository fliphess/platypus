# Stage 1: build a static binary.
FROM public.ecr.aws/docker/library/golang:1.26.10-trixie AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

# TARGETARCH is set by buildx for multi-platform builds. Compose's build does
# not set it, so fall back to the build container's architecture: a hardcoded
# arm64 produced unrunnable images on amd64 hosts (exec format error).
ARG TARGETARCH
ARG VERSION=dev
ENV CGO_ENABLED=0 GOOS=linux
RUN GOARCH="${TARGETARCH:-$(go env GOARCH)}" \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/platypus ./cmd/platypus

# Stage 2: nothing but the binary, the runtime files and CA certificates.
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/platypus /app/platypus
COPY internal/docs/pages /app/docs
COPY internal/web/templates /app/templates
COPY internal/web/static /app/static

ENV PLATYPUS_DOCS_DIR=/app/docs \
    PLATYPUS_TEMPLATES_DIR=/app/templates \
    PLATYPUS_STATIC_DIR=/app/static

# A numeric, non-root user: scratch has no /etc/passwd.
USER 10010:10010

EXPOSE 8080 8081
ENTRYPOINT ["/app/platypus"]
CMD ["web"]
