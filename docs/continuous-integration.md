# Release CI and local development checks

The [Release](../.github/workflows/release.yml) workflow runs on every push to
`main`. It publishes standalone binaries and a controller image for that exact
commit. Other branch pushes, pull requests and tag pushes do not publish.
GitHub prereleases are named `main-<full-commit-sha>` and point to the built commit.

## Release build

One Ubuntu job installs the pinned Go, Node.js and pnpm versions, builds the
frontend from the lockfile, and embeds it into every binary. It cross-compiles
with CGO disabled for every architecture advertised by the pinned Go toolchain
on the seven supported operating systems. Go 1.26.8 currently supplies 33 targets:

| System | Architectures |
| --- | --- |
| Linux | 386, amd64, arm, arm64, loong64, mips, mipsle, mips64, mips64le, ppc64, ppc64le, riscv64, s390x |
| Windows | 386, amd64, arm64 |
| macOS (`darwin`) | amd64, arm64 |
| FreeBSD | 386, amd64, arm, arm64 |
| OpenBSD | 386, amd64, arm, arm64, ppc64, riscv64 |
| NetBSD | 386, amd64, arm, arm64 |
| DragonFly | amd64 |

The binary's `version` command and filenames use `main-<full-commit-sha>`. CPU baselines
remain in `scripts/cross-build.py` (including amd64 v1, ARMv7 and soft-float MIPS).
Cross-compilation does not establish native runtime support on every target;
platform restrictions remain documented in the operation guides.
The legacy Bolt import used by Raft's migration helper is redirected through a
small bbolt adapter in `internal/boltcompat`, allowing MIPS, RISC-V and LoongArch
builds. GraphWAN's live Raft store continues to use the same bbolt implementation
and file format.

Each target produces one standalone binary, named
`graphwan-<tag>-<os>-<arch>` with `.exe` appended for Windows. CI uploads these
33 executables directly, together with `controller-image.txt` containing the
published image reference. The build manifest remains internal;
release preparation checks every binary's size and SHA-256 against it before
uploading. All targets must build successfully. CI also packages the same Linux
amd64 and arm64 binaries into a controller image using `Dockerfile`. The amd64
image must pass a version check and an HTTPS health check before publication.
It runs as a non-root user with a read-only root filesystem and a writable data
directory. Browser automation and live deployments do not run in CI.

Controller images are published to `ghcr.io/<owner>/<repository>:<full-commit-sha>`
with the repository name lowercased. Deployments must use the immutable
`ghcr.io/<owner>/<repository>@sha256:...` reference from `controller-image.txt`
or the workflow summary. The digest comes from BuildKit publication metadata;
it is never derived from the commit SHA or the executable checksum.
The image includes its executable and CA trust store; only `/data` needs persistent
storage. Kubernetes deployments use the image's entrypoint and pass controller
flags as `args`. Image publication uses `GITHUB_TOKEN` with `packages: write`.
Configure package visibility or image-pull credentials before deployment.

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
