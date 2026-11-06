# Client nodes

A client node lets another application, such as an outbound of a proxy client,
send its connections into a GraphWAN Network. The application decides which
connections use GraphWAN and resolves names itself; the client node takes IP
destinations and the Network routes them, for example to a node advertising
`0.0.0.0/0` as an exit.

On the network side a client node is a full Agent: it connects to the
controller, discovers and reports its endpoints, and reaches its peers with every
transport, including NAT hole punching. It differs only in what an embedded
outbound does not need:

- connections live in a user-space stack at the node's overlay address instead of
  a TUN interface, and no host routes or gateway rules are managed;
- it accepts no inbound connections;
- routes never pass through it: it is a source or a destination, never a transit
  hop, in controller, live and link-state routing alike;
- it advertises no subnets and connects only to regular Agent nodes.

## Add a client

1. Create the node's identity in the embedding application, or run
   `graphwan agent key --data-dir DIR` and take its public key.
2. Register the public key with `POST /api/v1/agents` (see
   [registration by public key](control-api.md#registration-by-public-key)), or
   enroll the Agent with a token instead.
3. Add the Agent to a Network as a node with `"client": true`, and connect it with
   Edges to the Agents it should use as gateways. With several Edges, the Network
   chooses among them by weight and Link health and fails over between them.

## Embedding

The `client` package runs a client node:

```go
c, err := client.Start(ctx, client.Config{
	Server:     "https://cp.example.com",
	CA:         caPEM,      // controller CA; empty trusts system roots
	PrivateKey: privateKey, // the registered Ed25519 identity
	StateDir:   dir,        // optional: keeps state across restarts
	Control:    control,    // socket options for every socket the node opens
	Lookup:     lookup,     // resolver for every name the node dials
})
conn, err := c.DialTCP(ctx, netip.MustParseAddrPort("10.42.0.3:443"))
pc, err := c.ListenUDP(ctx, netip.MustParseAddr("10.42.0.3"))
```

`Control` and `Lookup` should apply what the application applies to its own
connections to remote servers: bound interface, routing mark, platform socket
protection and its DNS. Otherwise the node's sockets can loop back into the
application's own TUN.

`DialTCP` fails at once for a destination that no node owns, so the application
can choose another way. While routes converge, after start or a Link change, it
waits for a route within the caller's context. The node keeps retrying its
controller connection, with a backoff of up to a minute, until it is closed.
