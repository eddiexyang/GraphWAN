package streamproxy

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/eWloYW8/GraphWAN/internal/testutil"
)

func TestBoundedStreamSetup(t *testing.T) {
	r := Request{Network: testutil.ID(1), Source: testutil.ID(2), Destination: testutil.ID(3), From: netip.MustParseAddrPort("10.0.0.1:1234"), To: netip.MustParseAddrPort("10.0.0.2:443"), Hops: 32}
	var b bytes.Buffer
	if err := WriteRequest(&b, r); err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadRequest(&b)
	if err != nil || decoded != r {
		t.Fatal(decoded, err)
	}
	for _, size := range []uint16{0, SetupLimit + 1, 65535} {
		var prefix [2]byte
		binary.BigEndian.PutUint16(prefix[:], size)
		if _, err := ReadRequest(bytes.NewReader(prefix[:])); err == nil {
			t.Fatalf("accepted frame size %d", size)
		}
	}
	for _, invalid := range []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:443"), netip.MustParseAddrPort("169.254.1.1:443"), netip.MustParseAddrPort("10.0.0.2:0"), netip.MustParseAddrPort("[::ffff:10.0.0.2]:443")} {
		r.To = invalid
		if err := r.Validate(); err == nil {
			t.Fatalf("accepted unsafe target %s", invalid)
		}
	}
}
