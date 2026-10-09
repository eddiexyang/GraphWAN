package agent

import (
	"context"
	"encoding/binary"
	"net"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/eWloYW8/GraphWAN/internal/forwarding"
	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/packetbuf"
	"github.com/eWloYW8/GraphWAN/internal/routing"
	"github.com/eWloYW8/GraphWAN/internal/testutil"
	"github.com/eWloYW8/GraphWAN/internal/tunnel"
)

type saturatedBatchTUN struct {
	tunnel.Device
	raw       []byte
	reads     int
	count     int
	writerRan *atomic.Bool
	drained   bool
	stop      context.CancelFunc
}

func (*saturatedBatchTUN) BatchSize() int            { return packetbuf.BatchSize }
func (*saturatedBatchTUN) WriteBatch([][]byte) error { return nil }
func (d *saturatedBatchTUN) ReadBatch(buffers [][]byte, sizes []int) (int, error) {
	if d.reads > 0 {
		d.drained = d.writerRan.Load()
		d.stop()
		return 0, net.ErrClosed
	}
	d.reads++
	for i := range buffers[:d.count] {
		sizes[i] = copy(buffers[i], d.raw)
	}
	return d.count, nil
}

func TestSaturatedTunnelBatchAllowsWriterOnSingleProcessor(t *testing.T) {
	for _, count := range []int{32, packetbuf.BatchSize} {
		t.Run(strconv.Itoa(count), func(t *testing.T) { runSaturatedTunnelBatch(t, count) })
	}
}

func runSaturatedTunnelBatch(t *testing.T, count int) {
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	state := testutil.Topology()
	snapshot, err := routing.Compile(state, state.Networks[0].Nodes[0].AgentID)
	if err != nil {
		t.Fatal(err)
	}
	queued := make(chan struct{}, 1)
	done := make(chan struct{})
	var writerRan atomic.Bool
	go func() {
		<-queued
		writerRan.Store(true)
		close(done)
	}()
	router, err := forwarding.New(snapshot,
		func(context.Context, model.ID, model.ID, []byte) error {
			t.Fatal("batch forwarding was lost")
			return nil
		},
		func(context.Context, model.ID, []byte) error { t.Fatal("packet delivered locally"); return nil },
		forwarding.BatchOptions{Send: func(_ context.Context, _, _ model.ID, frames [][]byte) error {
			if len(frames) != count {
				t.Fatal("full input batch was split", len(frames))
			}
			queued <- struct{}{}
			return nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 28)
	raw[0], raw[8], raw[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	source, destination := state.Networks[0].Nodes[0].Address.As4(), state.Networks[0].Nodes[1].Address.As4()
	copy(raw[12:16], source[:])
	copy(raw[16:20], destination[:])
	d := &saturatedBatchTUN{raw: raw, count: count, writerRan: &writerRan, stop: cancel}
	device := newRuntimeTunnel(d)
	r := &DataPlane{ctx: ctx}
	network := state.Networks[0].ID
	r.state.Store(&runtimeState{router: router, devices: map[model.ID]*runtimeTunnel{network: device}})
	r.readTunnelBatch(network, device, d)
	<-done
	if !d.drained {
		t.Fatal("saturated input read the next burst before the queued writer could run")
	}
}
