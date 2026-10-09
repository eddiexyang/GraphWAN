# Release CI and local development checks

The [Release](../.github/workflows/release.yml) workflow runs on every push to
`master`. It publishes standalone binaries and a controller image for that exact
commit. Other branch pushes, pull requests and tag pushes do not publish.
GitHub prereleases are named `sha-<full-commit-sha>` and point to the built commit.

## Release build

One Ubuntu job installs the pinned Go, Node.js and pnpm versions, builds the
frontend from the lockfile, and embeds it into the Linux amd64 and arm64
(aarch64) binaries. Two direct `go build` steps compile with CGO disabled and
the amd64 v1 / arm64 v8.0 CPU baselines. CI builds no other operating systems or
architectures and uses no Python build or packaging scripts.

The binary's `version` command and filenames use `sha-<full-commit-sha>`.
The two release assets are `graphwan-<tag>-linux-amd64` and
`graphwan-<tag>-linux-arm64`.

The multi-stage `Dockerfile` builds the frontend and Go binary directly from the
repository. Official Docker Actions build and publish the Linux amd64/arm64
controller image to `ghcr.io/<owner>/<repository>:<full-commit-sha>`.
The build action's `digest` output is exposed as the job's `image_digest` output
and included in the GitHub Release notes. Deployments use
`ghcr.io/<owner>/<repository>@sha256:...` with that published digest.
The image runs as a non-root user and includes its executable and CA trust store;
only `/data` needs persistent storage. Kubernetes uses the image's entrypoint and
passes controller flags as `args`. Image publication uses `GITHUB_TOKEN` with
`packages: write`. Configure package visibility or image-pull credentials before
deployment. CI does not perform live deployments.

Publication uses the repository's `GITHUB_TOKEN` with `contents: write` and
automatically generated release notes. Assets are uploaded to a draft before
publication. A failed upload can be retried by rerunning the workflow; an already
published release is left intact. No extra release secret is required. Toolchains
are pinned in `.go-version`, `.node-version` and `web/package.json`.

## Local core tests

Go tests cover:

- Topology validation and deterministic weighted routing.
- Disabled edges, revoked Agents and loop-free forwarding tables.
- Packet framing, malformed input and hop limits.
- Four cipher suites, authenticated handshakes, tampering and replay rejection.
- Durable configuration, transactional rollback and conflicting edits.
- Bidirectional cluster channels, leader changes, forwarded writes and reconnects
  over in-memory connections with only one permitted dialing direction.
- Idle probe failure detection, report suppression and observed endpoint lease
  renewal, using in-memory state and explicit timestamps.
- TCP access termination and three-Agent stream forwarding over TCP, QUIC,
  WS/WSS and gRPC; directional EOF, source tuple preservation, reverse opens,
  IPv6, WireGuard plaintext access, policy revocation and stream telemetry.
- Bounded stream setup, IPv6 fragment classification, cancellation and shutdown
  while an access handshake is incomplete.

Unit tests use in-memory state and private temporary files. TCP stream integration
tests use loopback peer listeners with simulated TUN and userspace application
TCP stacks. They require no administrator privileges or operating-system TUN
devices. Normal runs transfer multiple MiB; `-short` uses smaller payloads and
waits for peer admission before testing the stream.

The TCP stack is pinned to the upstream Go-build commit
`f57b8fc79db4`, including the [ARM64 race CAS fix](https://github.com/google/gvisor/commit/1b2946c4fa59c1a64643bce962140b5686062601).
This dependency requires Go 1.26.3; the pinned CI toolchain remains Go 1.26.8.

```sh
go test ./...
go test -race ./internal/agent ./internal/forwarding ./internal/peer ./internal/packet ./internal/streamproxy
go build -o bin/graphwan ./cmd/graphwan
pnpm --dir web install --frozen-lockfile
pnpm --dir web build
```

Commit rebuilt files in `internal/webui/dist` when frontend sources change.
Cross-platform binaries can be built on demand with `scripts/cross-build.py`;
packaging instructions are in [deployment](deployment.md).
