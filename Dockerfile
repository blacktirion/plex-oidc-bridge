# Synology has slightly older Docker versions sometimes, but standard BuildKit is usually fine.
# Use a multi-stage build to keep the image small.

# Stage 1: Build
FROM golang:1.25.4-alpine AS builder

WORKDIR /app

# Copy dependency files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY *.go ./

# Tidy and build
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=linux go build -o plex-oidc-bridge .

# Stage 2: Runtime
FROM alpine:latest

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/plex-oidc-bridge .

# Expose the port the app runs on
EXPOSE 8080

# Environment variables that can be overridden
ENV PORT=8080
ENV PUBLIC_URL=""
ENV OIDC_CLIENT_ID=""

# Volume for persistence
VOLUME ["/app/config"]

# Run the binary
CMD ["./plex-oidc-bridge"]
