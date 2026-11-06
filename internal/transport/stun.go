package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"time"
)

const maxSTUNTransactions = 32

type stunResult struct {
	address netip.AddrPort
	err     error
}
type stunTransaction struct {
	server netip.AddrPort
	result chan stunResult
}

// STUNBinding discovers the mapping of the actual peer data socket. It never
// opens a second socket, follows redirects, or treats STUN as peer admission.
// Callers can shorten the RFC 8489 retransmission schedule with their deadline.
func (h *UDP) STUNBinding(ctx context.Context, server netip.AddrPort) (netip.AddrPort, error) {
	server = netip.AddrPortFrom(server.Addr().Unmap(), server.Port())
	if !server.IsValid() || server.Port() == 0 || !stunUnicast(server.Addr()) {
		return netip.AddrPort{}, errors.New("invalid STUN server address")
	}
	request, id, err := stunRequest()
	if err != nil {
		return netip.AddrPort{}, err
	}
	transaction := &stunTransaction{server: server, result: make(chan stunResult, 1)}
	h.stunMu.Lock()
	if len(h.stunPending) >= maxSTUNTransactions {
		h.stunMu.Unlock()
		return netip.AddrPort{}, errors.New("STUN transaction limit reached")
	}
	if h.stunPending == nil {
		h.stunPending = make(map[[12]byte]*stunTransaction)
	}
	h.stunPending[id] = transaction
	h.stunMu.Unlock()
	defer func() { h.stunMu.Lock(); delete(h.stunPending, id); h.stunMu.Unlock() }()
	for attempt := range 7 {
		select {
		case <-h.done:
			return netip.AddrPort{}, net.ErrClosed
		default:
		}
		if err := h.writeDatagram(ctx, request, server); err != nil {
			return netip.AddrPort{}, err
		}
		wait := 500 * time.Millisecond << attempt
		if attempt == 6 {
			wait = 8 * time.Second
		}
		timer := time.NewTimer(wait)
		select {
		case result := <-transaction.result:
			timer.Stop()
			return result.address, result.err
		case <-ctx.Done():
			timer.Stop()
			return netip.AddrPort{}, ctx.Err()
		case <-h.done:
			timer.Stop()
			return netip.AddrPort{}, net.ErrClosed
		case <-timer.C:
		}
	}
	return netip.AddrPort{}, errors.New("STUN binding timed out")
}

// The socket reader only delivers replies for an outstanding random transaction
// AND its resolved server address. Malformed and unsolicited replies allocate no
// peer and send no response. STUN cannot consume QUIC or native UDP messages.
func (h *UDP) receiveSTUN(raw []byte, remote netip.AddrPort) bool {
	if len(raw) < 20 || raw[0]&0xc0 != 0 || binary.BigEndian.Uint32(raw[4:8]) != 0x2112a442 {
		return false
	}
	if len(raw) > 2048 || int(binary.BigEndian.Uint16(raw[2:4])) != len(raw)-20 || len(raw)%4 != 0 {
		return true
	}
	typeCode := binary.BigEndian.Uint16(raw[:2])
	if typeCode != 0x0101 && typeCode != 0x0111 {
		return true
	}
	id := [12]byte(raw[8:20])
	remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
	h.stunMu.Lock()
	transaction := h.stunPending[id]
	h.stunMu.Unlock()
	if transaction == nil || transaction.server != remote {
		return true
	}
	result, valid := parseSTUNResponse(raw, remote.Addr().Is4())
	if valid {
		select {
		case transaction.result <- result:
		default:
		}
	}
	return true
}

func stunUnicast(ip netip.Addr) bool {
	return ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}
