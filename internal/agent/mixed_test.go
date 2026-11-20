package agent

import (
	"bytes"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/packet"
	"github.com/eddiexyang/graphnet/internal/streamproxy"
	"github.com/eddiexyang/graphnet/internal/testutil"
)

// Every pairing of carriers on a two-hop path seals end to end: a TCP
// connection, where the path allows one, and a datagram from A reach C, each Edge's Link uses its own
// transport, only A and C hold their session, and C refuses B's seal for A.
func TestMixedCarriersSealEndToEnd(t *testing.T) {
	pairs := [][2]model.Transport{{model.QUIC, model.TCP}, {model.TCP, model.QUIC}, {model.QUIC, model.UDP}, {model.UDP, model.QUIC}, {model.QUIC, model.QUIC}, {model.TCP, model.UDP}, {model.UDP, model.TCP}}
	for _, pair := range pairs {
		t.Run(fmt.Sprintf("%s-%s", pair[0], pair[1]), func(t *testing.T) {
			agents, devices, state := graphAgents(t, pair[0], streamOptions{}, 3, 2, func(s *model.State) {
				for i := range s.Agents {
					port := s.Agents[i].ListenPort
					s.Agents[i].Endpoints = nil
					for j, carrier := range []model.Transport{model.UDP, model.TCP, model.QUIC} {
						s.Agents[i].Endpoints = append(s.Agents[i].Endpoints, model.Endpoint{ID: testutil.ID(30 + 3*i + j), Transport: carrier, Source: model.Manual, URL: fmt.Sprintf("%s://127.0.0.1:%d", carrier, port)})
					}
				}
				for i := range s.Networks[0].Edges {
					s.Networks[0].Edges[i].Transports = []model.Transport{pair[i]}
				}
			})
			network, nodes := state.Networks[0].ID, state.Networks[0].Nodes
			for i, edge := range state.Networks[0].Edges {
				waitCarrier(t, agents[i], edge.ID, pair[i])
			}

			// TCP from a packet-only first hop crosses as packets, which a
			// later stream hop refuses rather than run TCP over TCP.
			if pair[0] != model.UDP || pair[1] == model.UDP {
				transferApplication(t, devices[0], devices[2], nodes[2].Address)
			}

			devices[2].udp = make(chan []byte, 16)
			from := netip.AddrPortFrom(nodes[0].Address, 5000)
			to := netip.AddrPortFrom(nodes[2].Address, 5001)
			message := bytes.Repeat([]byte("sealed across carriers "), 50)
			got := sendUDP(t, devices[0], devices[2], packet.UDP(from, to, message))
			if source, destination, payload, ok := packet.UDPDatagram(got); !ok || source != from || destination != to || !bytes.Equal(payload, message) {
				t.Fatal("the datagram changed")
			}

			sealed := outgoingE2E(agents[0], network, nodes[2].ID)
			if sealed == nil || agents[2].e2eAccepted(network, nodes[0].ID, sealed.id) == nil {
				t.Fatal("no end-to-end session between the ends")
			}
			if agents[1].e2eAccepted(network, nodes[0].ID, sealed.id) != nil {
				t.Fatal("the relay holds the session")
			}
			request := streamproxy.Request{Network: network, Source: nodes[0].ID, Destination: nodes[2].ID, Conn: streamproxy.NewSessionID(), Sealer: nodes[1].ID, E2E: sealed.id, Channel: 1}
			if _, ok := agents[2].egressRecords(network, request); ok {
				t.Fatal("the egress accepted the relay's seal for the Source")
			}
		})
	}
}

// waitCarrier waits until agent's active Link on edge uses carrier.
func waitCarrier(t *testing.T, agent *DataPlane, edge model.ID, carrier model.Transport) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		for _, status := range agent.Report() {
			if status.EdgeID == edge && status.Active {
				if status.Transport != carrier {
					t.Fatalf("edge %s carried by %s, want %s", edge, status.Transport, carrier)
				}
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("edge %s has no active %s Link", edge, carrier)
}
