package agent

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/packet"
	"github.com/eWloYW8/GraphWAN/internal/streamproxy"
)

func outgoingE2E(r *DataPlane, network, node model.ID) *e2eSession {
	r.e2e.mu.Lock()
	defer r.e2e.mu.Unlock()
	if out := r.e2e.outgoing[e2ePeer{network, node}]; out != nil {
		return out.current
	}
	return nil
}

// A session through a relay is sealed by its ends: the egress opens records
// of the ingress's session toward it, which the relay does not hold, and it
// refuses a request that would have it send unsealed.
func TestTCPSessionIsSealedEndToEnd(t *testing.T) {
	agents, devices, state := graphAgents(t, model.TCP, streamOptions{}, 3, 2)
	sessionExchange(t, devices, state, 2, 1<<20, 4<<20, func() {
		if relaying(agents[1]) != 1 {
			t.Errorf("relayed chains %d", relaying(agents[1]))
		}
	})
	network, nodes := state.Networks[0].ID, state.Networks[0].Nodes
	sealed := outgoingE2E(agents[0], network, nodes[2].ID)
	if sealed == nil || agents[2].e2eAccepted(network, nodes[0].ID, sealed.id) == nil {
		t.Fatal("no end-to-end session between the ends")
	}
	if agents[1].e2eAccepted(network, nodes[0].ID, sealed.id) != nil {
		t.Fatal("the relay holds the session")
	}
	request := streamproxy.Request{Network: network, Source: nodes[0].ID, Destination: nodes[2].ID, Conn: streamproxy.NewSessionID()}
	if _, ok := agents[2].egressRecords(network, request); ok {
		t.Fatal("the egress accepted an unsealed session")
	}
	request.Sealer, request.E2E, request.Channel = nodes[0].ID, streamproxy.E2EID{1}, 1
	if _, ok := agents[2].egressRecords(network, request); ok {
		t.Fatal("the egress accepted an unknown end-to-end session")
	}
	request.Sealer, request.E2E = nodes[1].ID, sealed.id
	if _, ok := agents[2].egressRecords(network, request); ok {
		t.Fatal("the egress accepted another Node's seal for the Source")
	}
}

// An egress that lost its end-to-end sessions, as by a restart, refuses the
// next connection's first chain; the ingress waits for a new session and the
// connection opens.
func TestTCPSessionAfterEgressLostItsKeys(t *testing.T) {
	agents, devices, state := graphAgents(t, model.TCP, streamOptions{}, 3, 2)
	sessionExchange(t, devices, state, 2, 64<<10, 4<<20, nil)
	network, nodes := state.Networks[0].ID, state.Networks[0].Nodes
	before := outgoingE2E(agents[0], network, nodes[2].ID)
	agents[2].e2e.mu.Lock()
	clear(agents[2].e2e.incoming)
	agents[2].e2e.mu.Unlock()
	transferApplication(t, devices[0], devices[2], nodes[2].Address)
	if after := outgoingE2E(agents[0], network, nodes[2].ID); after == nil || after == before {
		t.Fatal("the ingress kept the lost session")
	}
}

// sendUDP writes a datagram from one device's application until another
// device receives it: the first may drop while the end-to-end session forms.
func sendUDP(t *testing.T, from, to *kernelTUN, raw []byte) []byte {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case from.packets <- kernelPacket{raw: bytes.Clone(raw)}:
		case <-time.After(time.Second):
		}
		select {
		case got := <-to.udp:
			return got
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatal("the datagram did not arrive")
	return nil
}

// A datagram through a relay is sealed by its ends: only the egress opens it,
// once, with the headers it was sent with, and it drops one that comes
// unsealed. An egress that lost its sessions has the ingress replace its own.
func TestPacketsAreSealedEndToEnd(t *testing.T) {
	agents, devices, state := graphAgents(t, model.UDP, streamOptions{}, 3, 2)
	network, nodes := state.Networks[0].ID, state.Networks[0].Nodes
	devices[2].udp = make(chan []byte, 16)
	from := netip.AddrPortFrom(nodes[0].Address, 5000)
	to := netip.AddrPortFrom(nodes[2].Address, 5001)
	message := []byte("a datagram sealed end to end")
	raw := packet.UDP(from, to, message)
	got := sendUDP(t, devices[0], devices[2], raw)
	if source, destination, payload, ok := packet.UDPDatagram(got); !ok || source != from || destination != to || !bytes.Equal(payload, message) {
		t.Fatal("the datagram changed")
	}

	seal := func() []byte {
		buf := make([]byte, len(raw), len(raw)+packet.Trailer)
		copy(buf, raw)
		sealed, ok, err := e2ePackets{agents[0]}.Seal(network, nodes[2].ID, buf)
		if err != nil || !ok || len(sealed) != len(raw)+packet.Trailer {
			t.Fatal("seal", ok, err)
		}
		return sealed
	}
	sealed := seal()
	if bytes.Contains(sealed, message) || !bytes.Equal(sealed[:packet.Readable(raw)], raw[:packet.Readable(raw)]) {
		t.Fatal("sealed the wrong bytes")
	}
	if _, err := (e2ePackets{agents[1]}).Open(network, nodes[0].ID, bytes.Clone(sealed), true); err == nil {
		t.Fatal("the relay opened the datagram")
	}
	hop := bytes.Clone(sealed)
	packet.DecrementIPHopLimit(hop)
	if opened, err := (e2ePackets{agents[2]}).Open(network, nodes[0].ID, hop, true); err != nil || !bytes.Equal(opened[udpPayload:], message) {
		t.Fatal("the egress did not open the datagram after a hop", err)
	}
	if _, err := (e2ePackets{agents[2]}).Open(network, nodes[0].ID, bytes.Clone(sealed), true); err == nil {
		t.Fatal("the egress opened the datagram twice")
	}
	if _, err := (e2ePackets{agents[2]}).Open(network, nodes[0].ID, bytes.Clone(raw), false); err == nil {
		t.Fatal("the egress took an unsealed datagram")
	}
	changed := seal()
	changed[23]++ // the destination port
	if _, err := (e2ePackets{agents[2]}).Open(network, nodes[0].ID, changed, true); err == nil {
		t.Fatal("the egress opened a datagram with changed headers")
	}

	before := outgoingE2E(agents[0], network, nodes[2].ID)
	agents[2].e2e.mu.Lock()
	clear(agents[2].e2e.incoming)
	agents[2].e2e.mu.Unlock()
	sendUDP(t, devices[0], devices[2], raw)
	if after := outgoingE2E(agents[0], network, nodes[2].ID); after == nil || after == before {
		t.Fatal("the ingress kept the lost session")
	}
}

// udpPayload is where an IPv4 UDP datagram's payload starts.
const udpPayload = 28
