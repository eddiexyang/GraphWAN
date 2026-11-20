# QUIC endpoints

Add a manual endpoint such as `quic://node.example.com:24752` in **Agents → Manage**,
then enable QUIC and the required IPv4/IPv6 direct methods on the Edge. Addresses
and DNS names require explicit ports, and QUIC endpoints do not accept URL paths.
Automatic discovery advertises TCP/UDP only; it does not infer QUIC endpoints.

QUIC and native UDP share the configured Agent UDP listen port. A manual URL
with another external port requires UDP forwarding to that listener.

## A stream Link

A QUIC Link is one bidirectional QUIC stream that carries the same
length-framed peer messages as a TCP Link: the Noise-authenticated peer
protocol, heartbeats, selection, packets and TCP session streams. Like a TCP
Link it carries TCP sessions as streams and refuses TCP packets, so TCP never
runs over TCP; unlike one it keeps working across a client's address change
and shares the UDP port, which suits mobile Agents.

## TLS and admission

The wire uses QUIC v1, TLS 1.3 and ALPN `graphnet.quic.v2`. Direct connections
verify the configured Agent Ed25519 key through its automatically renewed
certificate; a CA-issued certificate must validate against the system trust
store and endpoint hostname. Noise independently verifies both Agent identities
and the configured Edge, Network and transport. No 0-RTT data is enabled.

At most 512 incoming and outgoing connections may await Noise authentication
across both address families. A successful Noise handshake releases its slot
without closing the connection; TLS alone does not. Handshakes have a
five-second idle limit, established connections expire after fifteen idle
seconds and send QUIC keepalives every five. A stable stateless-reset key is
derived from the durable Agent identity with HKDF-SHA256.

## Sharing the port and staying silent

Every local QUIC connection ID is 16 bytes: `Q`, 7 random bytes and the first
8 bytes of an HMAC-SHA256 of those 8 under a key derived from the Agent's
identity. A datagram whose trailing token names no native peer from its address
goes to QUIC only when it is a QUIC v1 packet toward such an ID, or an Initial
from an address that knocked within the last minute. Anything else is dropped
without an answer, so a scan learns nothing: no TLS certificate, no stateless
reset and no version negotiation.

A dialer knocks before its Initial and again while it waits: kind `0x47`, the
8-byte Unix time, 8 random bytes and 16 bytes of HMAC-SHA256 keyed by a key
derived from the target Agent's public identity, which only Agents of its
deployment are given. A knock more than a minute from the receiver's clock is
ignored. See [peer-protocol.md](peer-protocol.md) for the native datagram
layout. QUIC's own path MTU discovery keeps its packets within the path, so a
Link's messages are never fragmented by GraphNet.
