FROM --platform=$BUILDPLATFORM node:24.21.0-bookworm-slim AS frontend
WORKDIR /src/web
RUN npm install --global pnpm@10.33.3
COPY web/package.json web/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm build

FROM --platform=$BUILDPLATFORM golang:1.26.8-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY internal/boltcompat/ ./internal/boltcompat/
RUN go mod download
COPY . .
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -trimpath -buildvcs=false -ldflags="-s -w -X main.version=$VERSION" \
    -o /out/graphnet ./cmd/graphnet

FROM scratch AS binaries
ARG TARGETARCH
ARG VERSION=dev
COPY --from=build /out/graphnet /graphnet-${VERSION}-linux-${TARGETARCH}

# Both images keep a shell and basic tools for debugging in place.
FROM debian:trixie-slim AS controller
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
ARG VERSION=dev
WORKDIR /usr/local/share/graphnet
COPY --from=build /out/graphnet /usr/local/bin/graphnet
COPY --from=frontend /src/internal/webui/dist/ ./
COPY --from=agent-amd64 /out/graphnet ./assets/agent/${VERSION}/linux-amd64
COPY --from=agent-arm64 /out/graphnet ./assets/agent/${VERSION}/linux-arm64
ENTRYPOINT ["/usr/local/bin/graphnet"]
CMD ["server", "--listen=0.0.0.0:8443", "--data-dir=/data"]
EXPOSE 8443

# The Agent manages TUN devices, routes and gateway firewall rules.
FROM debian:trixie-slim AS agent
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates iproute2 iptables nftables \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/graphnet /usr/local/bin/graphnet
ENTRYPOINT ["/usr/local/bin/graphnet"]
CMD ["agent", "run"]
