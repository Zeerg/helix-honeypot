ARG GO_VERSION=1.27.1

FROM golang:${GO_VERSION}-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go vet ./...
RUN go test ./...
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/helix-honeypot \
    ./cmd

FROM scratch

LABEL org.opencontainers.image.title="Helix Honeypot" \
      org.opencontainers.image.description="Bounded protocol honeypot" \
      org.opencontainers.image.licenses="MIT"

COPY --from=build /out/helix-honeypot /helix-honeypot
COPY config.docker.toml /etc/helix/config.toml
ENV HELIX_CONFIG=/etc/helix/config.toml
EXPOSE 8080 8081 9022 9053/udp 10250
USER 65532:65532
ENTRYPOINT ["/helix-honeypot"]
