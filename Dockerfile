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
COPY --from=frontend /src/internal/webui/dist/ ./internal/webui/dist/
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -trimpath -buildvcs=false -ldflags="-s -w -X main.version=$VERSION" \
    -o /out/graphwan ./cmd/graphwan

FROM scratch AS binaries
ARG TARGETARCH
ARG VERSION=dev
COPY --from=build /out/graphwan /graphwan-${VERSION}-linux-${TARGETARCH}

FROM gcr.io/distroless/static-debian12:nonroot AS controller
COPY --from=build /out/graphwan /usr/local/bin/graphwan
ENTRYPOINT ["/usr/local/bin/graphwan"]
CMD ["server", "--listen=0.0.0.0:8443", "--data-dir=/data"]
EXPOSE 8443
