package agent

import (
	"bytes"
	"encoding/binary"
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
	// The relay forwards each frame in the buffer it arrived in.
	if counters := agents[1].Counters(); counters["relay_forwarded_bytes"] < 2<<20 || counters["relay_copied_bytes"] != 0 {
		t.Fatalf("relay forwarded %d bytes, copied %d", counters["relay_forwarded_bytes"], counters["relay_copied_bytes"])
	}
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
	if bytes.Contains(sealed, message) || !bytes.Equal(sealed[:packet.HeaderLen(raw)], raw[:packet.HeaderLen(raw)]) {
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
	// A hop's change to the checksums the seal leaves out does not reach the
	// destination: it computes them again.
	checksum := seal()
	checksum[26] ^= 0xff // the UDP checksum
	checksum[10] ^= 0xff // the IPv4 header checksum
	if opened, err := (e2ePackets{agents[2]}).Open(network, nodes[0].ID, checksum, true); err != nil || !bytes.Equal(opened, raw) {
		t.Fatal("the egress did not restore the checksums", err)
	}
	// A later fragment has only its IP header readable, and opens unchanged.
	fragment := bytes.Clone(raw)
	binary.BigEndian.PutUint16(fragment[6:8], 3) // offset 24 bytes
	fragment[10], fragment[11] = 0, 0
	binary.BigEndian.PutUint16(fragment[10:12], ^checksum16(fragment[:20]))
	buf := make([]byte, len(fragment), len(fragment)+packet.Trailer)
	copy(buf, fragment)
	sealedFragment, ok, err := e2ePackets{agents[0]}.Seal(network, nodes[2].ID, buf)
	if err != nil || !ok || packet.HeaderLen(fragment) != 20 || bytes.Contains(sealedFragment[20:], fragment[20:28]) {
		t.Fatal("sealed a fragment", ok, err)
	}
	if opened, err := (e2ePackets{agents[2]}).Open(network, nodes[0].ID, sealedFragment, true); err != nil || !bytes.Equal(opened, fragment) {
		t.Fatal("the egress did not open a fragment", err)
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

// checksum16 is the one's complement sum of raw's 16-bit words.
func checksum16(raw []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(raw); i += 2 {
		sum += uint32(raw[i])<<8 | uint32(raw[i+1])
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return uint16(sum)
}
