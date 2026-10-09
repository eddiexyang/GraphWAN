# TCP stream forwarding

GraphWAN terminates TCP at its access boundaries and forwards application bytes
over the configured graph. TUN and WireGuard retain their existing addresses,
routes and application access. A TCP SYN enters a userspace TCP stack on the
first Agent; the last Agent opens a new access-side TCP connection with the
original source/destination addresses and ports. Each transit Agent copies bytes
between two authenticated streams. Inner TCP headers, ACKs, congestion windows
and retransmissions stay at the access boundaries.

UDP and ICMP keep their existing IP datagram forwarding path. Native UDP remains
unreliable and carries no TCP bytes. TCP packets arriving on the old packet
path are refused, preventing an implicit TCP-over-TCP fallback.

## Configuration and upgrades

Keep the existing Network, Node, virtual address and Edge configuration. Each
Edge on a TCP route must permit at least one reachable reliable transport: TCP,
QUIC, WS, WSS or gRPC. Interface discovery already supplies TCP endpoints;
QUIC, WS/WSS and gRPC require their existing manual endpoints. A UDP-only Edge
can still carry datagrams; TCP connections through it are refused.

Upgrade Agents in a connected Network together. Stream admission and directional
close records require the new peer extension. Mixed versions cannot exchange
TCP application streams. The controller configuration schema is unchanged.

Stream opens use the same compiled weighted/live routes and address ownership
directory as datagrams. A destination in an advertised subnet terminates at its
owning Agent. Existing external routes, gateway mode and SNAT still apply to the
access TCP packets. A WireGuard leaf terminates at its attaching Agent; its
authenticated plaintext TCP packets enter the local TCP stack. No controller
relay or additional proxy listening port is required.

Native direct TCP byte connections also inherit the kernel's default unsent-byte
backlog policy. Admission removes the packet carrier's explicit 64-KiB
`TCP_NOTSENT_LOWAT` bound before application bytes begin. Packet Links retain
their existing bounded backlog; no host-wide TCP setting is changed.

On Linux native TUN networks without WireGuard access leaves, access TCP uses
host segmentation offload. Packet-buffer slices and their virtio checksum/GSO
metadata are written directly to TUN with `writev`, following
[sing-tun's native writer](https://github.com/SagerNet/sing-tun/blob/dev/tun_linux_gvisor.go).
The kernel handles segmentation and checksum completion. Other adapters retain
packet batching and the existing WireGuard access path.
Native GSO output calls the TUN writer synchronously, retaining the stack's
packet reference and avoiding a cloned packet queue and writer-goroutine wakeup.
Its nonblocking descriptor reports backpressure to the stack so endpoint locks
cannot wait on TUN readiness during close or recovery.
The access link advertises the native writer's 65535-byte GSO bound instead of
the generic channel endpoint's 32-KiB bound. Byte relays read directly into
record framing and endpoint send storage, retaining socket backpressure and
directional EOF without a second relay-buffer copy.
Native TCP gather writes remain available through the admission reader's
transparent read-ahead wrapper. This keeps accepted TCP streams on the same
`writev` path as outgoing streams and avoids flattening each ciphertext batch.
TLS and other framed carriers retain their transport-owned writes.
TCP packet channels reserve their existing transport length prefixes directly
in encrypted record storage, permitting one contiguous write without a framing
copy or separate small prefix vectors. Native byte streams retain gather writes
through their admission reader, using the same independent encrypted records.
Encrypted records, nonces and the wire protocol are unchanged.

Native Linux TUN reads also preserve TCP GSO packets until they reach the access
stack. Admission checks the size of each kernel-described IP segment against
the Network MTU and retains the same source/destination ownership checks.
Native TCP is read directly into owned stack storage; kernel-validated and
partial TCP checksum metadata is preserved through admission, avoiding an
extra full-payload copy and duplicate software checksum passes. UDP GSO is
still split into independent, fully checksummed IP datagrams before forwarding;
WireGuard and ordinary access packets retain their full-packet MTU checks.
Native TUN reads drain immediately available UDP datagrams into bounded batches
without waiting for more traffic. A UDP GSO packet that exceeds the remaining
batch slots is retained for the next read. TCP retains its owned GSO fast path.
One poll-descriptor callback and virtio-header buffer serve each bounded read
burst, avoiding per-packet callback and descriptor reference setup.
After a multi-packet ingress batch, forwarding yields its execution quantum so queued
packet writers can drain even when one processor handles continuous TUN input.

Access TCP uses standard NewReno loss recovery. SACK is disabled for these
host-local connections because the virtual stack's SACK pipe calculation can
retain stale outstanding segments after a receiver window shrinks and then
block delivery behind repeated retransmission timeouts. Graph byte sockets
use the operating system's default TCP behavior.
The local stack also disables its default RACK flag: RACK requires SACK, while
leaving it enabled suppresses the NewReno fast-recovery branch.
The access-side transmit queue defaults to 32 KiB and grows to at most 128 KiB,
following sing-tun's host-local stack. Its receive side retains the stack's
existing policy.

## Authentication and connection selection

Every new byte connection uses the existing configured Network/Edge Noise
handshake, identities, cipher, endpoint fingerprint, family, scope and candidate
policy. Its encrypted introduction includes `stream: true`. Plain UDP cannot
select this mode. Removing an Edge or revoking a candidate closes its streams.

For directly reachable peers, each application flow opens an independent
connection. Selection prefers the configured candidate, then known healthy
candidate RTTs; failed candidates fall through within the setup budget. This
keeps unrelated flows off a shared outer TCP socket.

The normal reachable-side Link dialer also establishes an authenticated reverse
carrier with `stream_mux: true`. A ready byte `M` in each direction confirms
carrier support before starting yamux. Its independent logical streams allow a
peer with no dialable endpoint to receive application streams. The physical
carrier shares its transport's congestion control; TCP carriers share that
socket's head-of-line blocking. Directly reachable opens retain their independent
connections. Native QUIC carriers have a single bidirectional stream underneath
yamux; the packet Link's QUIC datagrams remain separate.

Streams are pinned after opening. Later routing/preference changes affect new
connections. A transport failure resets the access TCP connection; application
protocols handle reconnecting. The runtime never replays previously sent bytes
onto another connection. Endpoint refreshes, display edits, MTU changes and live
route updates preserve compatible access TCP state. Address ownership and
WireGuard access-identity changes replace that network's access stack.

## Byte and route records

A dedicated connection continues to use peer Data messages (wire kind 5) and the
existing Noise session encryption. The encrypted plaintext has a one-byte type:

| Type | Contents |
| --- | --- |
| 1 | One or more application bytes, at most `secure.MaxPlaintext - 1`. |
| 2 | Directional EOF, exactly one byte. |
| 3 | EOF acknowledgment, exactly one byte. |

Writes split bytes into bounded records without preserving application write
boundaries. Records from an already available application write are sent in
batches of at most 32 through the existing authenticated channel. EOF closes
the writing direction while the opposite direction stays
readable. A receiver confirms EOF after consuming preceding bytes. Normal close
waits up to three seconds for the authenticated acknowledgment of its own EOF
before canceling the underlying connection. This prevents buffered QUIC/gRPC
responses from being discarded by early connection cancellation.

The first application bytes contain a two-byte unsigned big-endian JSON length,
followed by at most 512 bytes of JSON:

```json
{
  "network": "<32-character Network ID>",
  "source": "<source Node ID>",
  "destination": "<destination Node ID>",
  "from": "10.42.0.1:34567",
  "to": "10.42.0.3:443",
  "hops": 31
}
```

Node IDs and IP ownership must agree with the current directory. The Network
must agree with the authenticated channel and ingress must be a configured
neighbor. Source reflection, unknown destinations, zero ports, loopback,
link-local, mapped-address and cross-family destinations are rejected. The open
starts with hop limit 32 and decrements it at each graph hop. A transit open
cannot return to its ingress neighbor or exhaust the hop limit.

The receiver returns one byte: `0` after the target connection and all downstream
opens succeed, or `1` on a target/open refusal. Application bytes follow only
after success. Multiplexed carrier streams carry these same route/application
bytes with yamux's directional FIN and flow control.

## Limits and lifecycle

The end-to-end open budget is ten seconds; individual candidate attempts are
bounded to three seconds. Each Mesh allows 256 live/pending dedicated streams,
carrier connections and carrier logical streams combined. Each network access
stack allows 256 inbound TCP requests/connections and a finite 2048-packet local
output queue. Stream records bypass the packet Link's dropping queues and use
transport flow control. Relay buffers are 32 KiB per direction. Carriers have
eight pending accepts, a 1 MiB per-stream window, ten-second keepalives and write
timeout, and three-second stream open/close timeouts.

IPv6 fragments followed by additional extension headers use an access-side
transport classification cache. It holds at most 128 fragment identities and
256 KiB of unclassified packets for ten seconds. Once the initial fragment
arrives, UDP fragments continue unchanged and TCP fragments enter local
reassembly. Overflow and expiry drop unclassified fragments.

Noise's existing one-hour session lifetime and `2^32` message bound also apply to
byte connections. Active streams reaching either bound close and applications
must reconnect; transparent rekey/migration of application streams is not
implemented. Packet Links continue their existing fresh-handshake renewal.

Agent reports include stream bytes in the Link counters for the corresponding
transport and local/remote IP path. The totals include stream setup and carrier
framing. Transit stream bytes are counted at each adjacent connection.

Tests cover multi-megabyte three-Agent transfers over all five reliable carriers,
EOF responses, source tuple preservation, reverse opens, IPv6, WireGuard plaintext
access in both directions, configuration refresh/revocation, shutdown during an
incomplete handshake, cancellation, and bounded malformed-input handling. They
use simulated TCP/TUN access and loopback peer sockets without administrator
privileges. Throughput on real lossy/long-RTT paths still requires deployment
measurement.
