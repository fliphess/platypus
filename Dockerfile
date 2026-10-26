# Stage 1: build a static binary.
FROM public.ecr.aws/docker/library/golang:1.27.3-trixie AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

ARG TARGETARCH=arm64
ARG VERSION=dev
ENV CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH}
RUN go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/platypus ./cmd/platypus

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
