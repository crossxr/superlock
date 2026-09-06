# syntax=docker/dockerfile:1
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Install build deps
RUN apk add --no-cache git ca-certificates tzdata

# Copy deps first (cache layer)
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o /superlock-server \
    ./cmd/server

# ---- Runtime image ----
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /superlock-server /superlock-server
COPY --from=builder /app/migrations /migrations

EXPOSE 8080

ENTRYPOINT ["/superlock-server"]
