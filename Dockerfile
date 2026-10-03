# Multi-stage build: static server binary, minimal runtime with CA certs,
# non-root user. The image ships only cfdoh (the server component).
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/jnuse/cfdoh/internal/httpapi.Version=${VERSION}" \
    -o /out/cfdoh ./cmd/cfdoh

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S cfdoh && adduser -S cfdoh -G cfdoh
COPY --from=build /out/cfdoh /usr/local/bin/cfdoh
USER cfdoh
ENV HOST=0.0.0.0 PORT=8787
VOLUME /var/lib/cfdoh
ENV CACHE_PERSIST_PATH=/var/lib/cfdoh/cache.json
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8787/health || exit 1
ENTRYPOINT ["cfdoh"]
