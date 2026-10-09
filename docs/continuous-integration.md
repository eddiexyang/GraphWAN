# Release CI and local development checks

The [Release workflow](../.github/workflows/release.yml) runs on pushes to
`master`. It builds Linux amd64 and arm64 binaries and a multi-platform controller
image through [Docker Bake](../docker-bake.hcl). The controller image contains the
built web assets and both Agent binaries. GitHub Releases use `sha-COMMIT` tags;
the image is tagged with the source commit and the release records its digest.

Publication uses the repository's `GITHUB_TOKEN` with `contents: write` and
`packages: write`. Binaries are uploaded to a draft release before publication.
An already published release is left intact. This workflow builds and publishes;
run the tests below before authorizing a release push.

## Local verification

The Go suites cover topology and weighted routing, packet validation and
framing, all four ciphers, authenticated admission and replay rejection,
persistence and control reconciliation, peer convergence, and endpoint discovery.
Tests use private temporary files, in-memory transports and loopback sockets.
They require no administrator privileges or operating-system TUN interfaces.

```sh
go test -mod=readonly -race ./...
go test -mod=readonly ./internal/transport -run '^$' -bench BenchmarkTransportFraming -benchmem
```

The packet forwarding regression starts three real Agent dataplanes with
in-memory TUNs. Only the middle Agent advertises a reachable entrance. It checks
bidirectional TCP headers, options, sequence numbers and payload over both TCP
and UDP peer transports, preserving the normal transit IP hop decrement. A
counting TCP proxy verifies that new application tuples reuse the physical
connections established during convergence.

Framing compatibility tests decode optimized batches through the original
single-message receiver for every cipher. They check immutable caller buffers,
independent authenticated records, cancellation and malformed-input rejection.
The transport benchmark compares copying, gather writes and producer-framed
records with an in-memory sink. Its timings measure framing CPU/copy overhead;
they exclude encryption, kernel I/O and network latency, and are not an
end-to-end throughput measurement.

## Packet encapsulation and deployment

TCP/IP packets use the established peer Links with their original wire framing.
The implementation reserves existing transport length prefixes alongside the
encrypted records, avoiding another framing copy. Transparent admission wrappers
preserve gather writes. Cryptographic records, authentication, candidate
convergence, transport policy and application connection lifetimes remain intact.

The earlier TCP access-proxy build rejects TCP on the packet path. Coordinate
Agent upgrades across a Network when replacing that build with packet forwarding;
mixed versions can interrupt TCP even while the control plane and UDP remain
available. Preserve Agent identity/state and publish verified binaries before
starting the rollout. Verify new connections, existing tunnel reuse and the
required service endpoints on the deployed network.
