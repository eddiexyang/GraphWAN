package secure

import (
	"bytes"
	"testing"

	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/testutil"
)

func e2eConfigs(t *testing.T) (E2EConfig, E2EConfig) {
	a, b := configs(t)
	a.Cipher, b.Cipher = model.AES128GCM, model.AES128GCM
	ea := E2EConfig{Network: a.Network, Local: a.Local, Peer: a.Peer, Cipher: a.Cipher, Identity: a.Identity, PeerIdentity: a.PeerIdentity, Initiator: true}
	eb := E2EConfig{Network: b.Network, Local: b.Local, Peer: b.Peer, Cipher: b.Cipher, Identity: b.Identity, PeerIdentity: b.PeerIdentity}
	return ea, eb
}

func run(t *testing.T, initiator, responder *Handshake) (*Session, *Session, error) {
	t.Helper()
	message, _, err := initiator.Write()
	if err != nil {
		return nil, nil, err
	}
	if _, err := responder.Read(message); err != nil {
		return nil, nil, err
	}
	if message, _, err = responder.Write(); err != nil {
		return nil, nil, err
	}
	if _, err := initiator.Read(message); err != nil {
		return nil, nil, err
	}
	message, as, err := initiator.Write()
	if err != nil {
		return nil, nil, err
	}
	bs, err := responder.Read(message)
	return as, bs, err
}

// Two Nodes agree on a session whose channels carry ordered messages with no
// nonce on the wire; any other channel, index or byte fails to open.
func TestEndToEndChannels(t *testing.T) {
	ea, eb := e2eConfigs(t)
	initiator, err := NewEndToEndHandshake(ea)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := NewEndToEndHandshake(eb)
	if err != nil {
		t.Fatal(err)
	}
	as, bs, err := run(t, initiator, responder)
	if err != nil || as == nil || bs == nil {
		t.Fatal("handshake", err)
	}
	message := []byte("end-to-end record")
	seal := func(channel, index uint32) []byte {
		buf := make([]byte, len(message), len(message)+TagSize)
		copy(buf, message)
		return as.SealChannel(channel, index, buf)
	}
	sealed := seal(7, 3)
	if len(sealed) != len(message)+TagSize {
		t.Fatalf("sealed %d bytes", len(sealed))
	}
	if opened, err := bs.OpenChannel(7, 3, bytes.Clone(sealed)); err != nil || !bytes.Equal(opened, message) {
		t.Fatal("open", err)
	}
	for _, wrong := range [][2]uint32{{7, 4}, {8, 3}, {0, 3}} {
		if _, err := bs.OpenChannel(wrong[0], wrong[1], bytes.Clone(sealed)); err == nil {
			t.Fatalf("opened as channel %d message %d", wrong[0], wrong[1])
		}
	}
	tampered := bytes.Clone(sealed)
	tampered[0] ^= 1
	if _, err := bs.OpenChannel(7, 3, tampered); err == nil {
		t.Fatal("opened a changed message")
	}
	// The other direction has its own key.
	if _, err := as.OpenChannel(7, 3, bytes.Clone(sealed)); err == nil {
		t.Fatal("a sender opened its own message")
	}
}

// A Link handshake cannot complete an end-to-end one between the same Nodes.
func TestEndToEndHandshakeIsDistinct(t *testing.T) {
	ea, eb := e2eConfigs(t)
	link := Config{Network: eb.Network, Edge: testutil.ID(2), Local: eb.Local, Peer: eb.Peer, Transport: model.UDP, Cipher: eb.Cipher, Identity: eb.Identity, PeerIdentity: eb.PeerIdentity}
	initiator, err := NewEndToEndHandshake(ea)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := NewHandshake(link)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(t, initiator, responder); err == nil {
		t.Fatal("a Link handshake completed an end-to-end one")
	}
}

// Packets open out of order within the window, each once, with the headers
// they were sealed with; their nonces never meet a channel's.
func TestEndToEndPackets(t *testing.T) {
	ea, eb := e2eConfigs(t)
	initiator, err := NewEndToEndHandshake(ea)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := NewEndToEndHandshake(eb)
	if err != nil {
		t.Fatal(err)
	}
	as, bs, err := run(t, initiator, responder)
	if err != nil {
		t.Fatal(err)
	}
	ad, body := []byte("headers"), []byte("datagram")
	seal := func() []byte {
		buf := make([]byte, len(body), len(body)+TagSize+PacketSequence)
		copy(buf, body)
		sealed, err := as.SealPacket(ad, buf)
		if err != nil {
			t.Fatal(err)
		}
		return sealed
	}
	first, second := seal(), seal()
	if len(first) != len(body)+TagSize+PacketSequence {
		t.Fatalf("sealed %d bytes", len(first))
	}
	if opened, err := bs.OpenPacket(ad, bytes.Clone(second)); err != nil || !bytes.Equal(opened, body) {
		t.Fatal("open", err)
	}
	if opened, err := bs.OpenPacket(ad, bytes.Clone(first)); err != nil || !bytes.Equal(opened, body) {
		t.Fatal("open out of order", err)
	}
	if _, err := bs.OpenPacket(ad, bytes.Clone(first)); err == nil {
		t.Fatal("opened a packet twice")
	}
	third := seal()
	if _, err := bs.OpenPacket([]byte("Headers"), bytes.Clone(third)); err == nil {
		t.Fatal("opened with changed headers")
	}
	if _, err := bs.OpenChannel(0, 3, bytes.Clone(third[:len(third)-PacketSequence])); err == nil {
		t.Fatal("a packet opened as a channel message")
	}
	if opened, err := bs.OpenPacket(ad, third); err != nil || !bytes.Equal(opened, body) {
		t.Fatal("a failed open used the sequence", err)
	}
}
