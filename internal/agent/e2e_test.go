package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/packet"
	"github.com/eWloYW8/GraphWAN/internal/secure"
	"github.com/eWloYW8/GraphWAN/internal/streamproxy"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
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

// renewE2E has r start a new end-to-end session toward node now, as it does
// before the current one ages out.
func renewE2E(t *testing.T, r *DataPlane, network, node model.ID) {
	t.Helper()
	state := r.state.Load()
	peer := e2ePeer{network, node}
	r.e2e.mu.Lock()
	out := r.e2e.outgoing[peer]
	raw, ok := []byte(nil), false
	if out != nil {
		raw, ok = r.startE2ELocked(state, peer, out, time.Now())
	}
	r.e2e.mu.Unlock()
	if !ok {
		t.Fatal("no session to renew")
	}
	r.sendE2E(state, peer, raw)
}

// A session renewed during a 64 MiB transfer leaves the connection on its
// session; the next connection takes the new one.
func TestTCPSessionKeepsItsKeyAcrossRenewal(t *testing.T) {
	agents, devices, state := graphAgents(t, model.TCP, streamOptions{}, 3, 2)
	network, nodes := state.Networks[0].ID, state.Networks[0].Nodes
	var before *e2eSession
	sessionExchange(t, devices, state, 2, 64<<20, 32<<20, func() {
		before = outgoingE2E(agents[0], network, nodes[2].ID)
		renewE2E(t, agents[0], network, nodes[2].ID)
		waitFor(t, 10*time.Second, "the renewed session", func() bool {
			current := outgoingE2E(agents[0], network, nodes[2].ID)
			return current != nil && current != before
		})
	})
	after := outgoingE2E(agents[0], network, nodes[2].ID)
	transferApplication(t, devices[0], devices[2], nodes[2].Address)
	after.mu.Lock()
	used := after.channel
	after.mu.Unlock()
	if used == 0 || agents[2].e2eAccepted(network, nodes[0].ID, after.id) == nil {
		t.Fatal("the next connection did not use the renewed session")
	}
}

// A record changed between the relay and the egress, where only the ends'
// seal protects it, resets the connection at both ends after a correct
// prefix: no changed byte is delivered.
func TestTCPSessionChangedRecordResets(t *testing.T) {
	var proxy net.Listener
	tamper := make(chan struct{})
	agents, devices, state := graphAgents(t, model.TCP, streamOptions{}, 3, 2, func(s *model.State) {
		var err error
		if proxy, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { proxy.Close() })
		target := fmt.Sprintf("127.0.0.1:%d", s.Agents[2].ListenPort)
		go tamperingProxy(proxy, target, tamper)
		// Only B dials C, through the proxy; nobody dials B.
		s.Agents[2].Endpoints[0].URL = "tcp://" + proxy.Addr().String()
		s.Agents[1].Endpoints[0].URL = "tcp://127.0.0.1:1"
	})
	address := state.Networks[0].Nodes[2].Address
	listener, err := gonet.ListenTCP(devices[2].stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(address.As4()), Port: 8093}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	sent := make([]byte, 16<<20)
	rand.Read(sent)
	type result struct {
		got []byte
		err error
	}
	served := make(chan result, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			served <- result{nil, err}
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(30 * time.Second))
		got, err := io.ReadAll(conn)
		served <- result{got, err}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := gonet.DialContextTCP(ctx, devices[0].stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(address.As4()), Port: 8093}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := conn.Write(sent[:1<<20]); err != nil {
		t.Fatal(err)
	}
	close(tamper)
	_, writeErr := conn.Write(sent[1<<20:])
	if writeErr == nil {
		_, writeErr = conn.Read(make([]byte, 1))
	}
	r := <-served
	reset := func(err error) bool { return err != nil && strings.Contains(err.Error(), "reset") }
	if !reset(r.err) || !reset(writeErr) {
		t.Fatalf("not reset at both ends: egress %v, ingress %v", r.err, writeErr)
	}
	if !bytes.Equal(r.got, sent[:len(r.got)]) {
		t.Fatal("a changed byte reached the server")
	}
	if relaying(agents[1]) != 0 {
		t.Fatal("the relay kept the chain")
	}
}

// tamperingProxy forwards Link connections to target. Once tamper is closed
// it changes the last byte of the next frame toward target that carries
// sealed records, which lie outside the Link's seal.
func tamperingProxy(listener net.Listener, target string, tamper <-chan struct{}) {
	var once sync.Once
	for {
		in, err := listener.Accept()
		if err != nil {
			return
		}
		out, err := net.Dial("tcp", target)
		if err != nil {
			in.Close()
			continue
		}
		go func() { io.Copy(in, out); in.Close() }()
		go func() {
			defer out.Close()
			var prefix [4]byte
			for {
				if _, err := io.ReadFull(in, prefix[:]); err != nil {
					return
				}
				message := make([]byte, binary.BigEndian.Uint32(prefix[:]))
				if _, err := io.ReadFull(in, message); err != nil {
					return
				}
				select {
				case <-tamper:
					// [sealed kind 6][nonce][header and tag][records]
					if len(message) > 1+secure.Overhead+19+streamproxy.RecordOverhead && message[0] == 6 {
						once.Do(func() { message[len(message)-1] ^= 0xff })
					}
				default:
				}
				if _, err := out.Write(append(prefix[:], message...)); err != nil {
					return
				}
			}
		}()
	}
}

// A sealed datagram's IP header stays a router's: a relay takes its hop
// limit, drops it when the limit runs out and tells the source, and a
// datagram that has hops left arrives opened, with its checksums right.
func TestSealedPacketsExpireInTransit(t *testing.T) {
	agents, devices, state := graphAgents(t, model.UDP, streamOptions{}, 3, 2)
	network, nodes := state.Networks[0].ID, state.Networks[0].Nodes
	devices[0].icmp = make(chan []byte, 16)
	devices[2].udp = make(chan []byte, 16)
	waitFor(t, 10*time.Second, "end-to-end sessions", func() bool {
		return outgoingE2E(agents[0], network, nodes[2].ID) != nil && outgoingE2E(agents[1], network, nodes[0].ID) != nil
	})
	from := netip.AddrPortFrom(nodes[0].Address, 5000)
	to := netip.AddrPortFrom(nodes[2].Address, 5001)
	withTTL := func(ttl byte) []byte {
		raw := packet.UDP(from, to, []byte("hop limited"))
		raw[8] = ttl
		raw[10], raw[11] = 0, 0
		binary.BigEndian.PutUint16(raw[10:12], ^checksum16(raw[:20]))
		return raw
	}
	// TTL 1 runs out at the relay B.
	devices[0].packets <- kernelPacket{raw: withTTL(1)}
	select {
	case reply := <-devices[0].icmp:
		if netip.AddrFrom4([4]byte(reply[12:16])) != nodes[1].Address || reply[20] != 11 || !bytes.Equal(reply[48:56], withTTL(1)[20:28]) {
			t.Fatalf("not B's time exceeded for the datagram: % x", reply[:min(len(reply), 56)])
		}
	case got := <-devices[2].udp:
		t.Fatalf("a datagram with no hops left arrived: % x", got[:28])
	case <-time.After(5 * time.Second):
		t.Fatal("no time exceeded")
	}
	// TTL 2 arrives with one hop left.
	got := sendUDP(t, devices[0], devices[2], withTTL(2))
	want := withTTL(1) // the relay took a hop
	if !bytes.Equal(got, want) {
		t.Fatalf("arrived % x, want % x", got[:28], want[:28])
	}
}

// Datagrams as large as the network's MTU travel sealed over UDP and QUIC
// Links.
func TestSealedPacketsOfFullSize(t *testing.T) {
	for _, carrier := range []model.Transport{model.UDP, model.QUIC} {
		t.Run(string(carrier), func(t *testing.T) {
			agents, devices, state := graphAgents(t, carrier, streamOptions{}, 3, 2)
			network, nodes := state.Networks[0].ID, state.Networks[0].Nodes
			devices[2].udp = make(chan []byte, 16)
			waitFor(t, 10*time.Second, "an end-to-end session", func() bool { return outgoingE2E(agents[0], network, nodes[2].ID) != nil })
			mtu := int(state.Networks[0].MTU)
			payload := make([]byte, mtu-28)
			rand.Read(payload)
			raw := packet.UDP(netip.AddrPortFrom(nodes[0].Address, 5000), netip.AddrPortFrom(nodes[2].Address, 5001), payload)
			if len(raw) != mtu {
				t.Fatalf("datagram of %d bytes, MTU %d", len(raw), mtu)
			}
			got := sendUDP(t, devices[0], devices[2], raw)
			if _, _, p, ok := packet.UDPDatagram(got); !ok || !bytes.Equal(p, payload) {
				t.Fatal("the full-size datagram changed")
			}
		})
	}
}
