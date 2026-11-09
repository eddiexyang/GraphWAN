package agent

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/forwarding"
	"github.com/eWloYW8/GraphWAN/internal/gateway"
	"github.com/eWloYW8/GraphWAN/internal/linkstate"
	"github.com/eWloYW8/GraphWAN/internal/mesh"
	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/packet"
	"github.com/eWloYW8/GraphWAN/internal/packetbuf"
	"github.com/eWloYW8/GraphWAN/internal/tunnel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type DataPlaneOptions struct {
	TunnelFactory tunnel.Factory
	BindHost      string
	Logger        *slog.Logger
	Endpoints     func([]model.Endpoint) error
	// Embedded runs the data plane inside another application, such as an
	// outbound of a proxy client: it manages no host gateway rules and listens
	// on an ephemeral port instead of the configured one.
	Embedded bool
	// legacyStreams makes this Agent carry streams without TCP sessions, as
	// older versions do. Tests use it for mixed versions.
	legacyStreams bool
	// kernelEgress has an Agent with test devices use the host's kernel
	// egress, as one with real TUN devices does.
	kernelEgress bool
}
type runtimeState struct {
	snapshot model.Snapshot
	router   *forwarding.Router
	mesh     *mesh.Mesh
	devices  map[model.ID]*runtimeTunnel
	tcp      map[model.ID]*runtimeTCP
	// selfAddress is this Agent's overlay address per network, for replay
	// requests of its TCP sessions.
	selfAddress map[model.ID]netip.Addr
	// keys are the Agent keys of the directory's other Nodes.
	keys map[e2ePeer]ed25519.PublicKey
}

type DataPlane struct {
	gateway       gateway.Manager
	identity      ed25519.PrivateKey
	options       DataPlaneOptions
	ctx           context.Context
	cancel        context.CancelFunc
	applyMu       sync.Mutex
	state         atomic.Pointer[runtimeState]
	wg            sync.WaitGroup
	closed        bool
	lastRoutes    *model.RouteUpdate
	discoveryWake chan struct{}
	repairWake    chan struct{}
	linkState     *linkstate.Engine
	damper        *edgeDamper
	sessions      sessions
	e2e           e2eSessions
	// kernelEgress: a session's egress connects to a destination on this host
	// with a kernel socket rather than through the TUN.
	kernelEgress bool
}

func NewDataPlane(parent context.Context, identity ed25519.PrivateKey, options DataPlaneOptions) (*DataPlane, error) {
	if len(identity) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid agent identity")
	}
	kernel := !options.Embedded && (options.TunnelFactory == nil || options.kernelEgress)
	if options.TunnelFactory == nil {
		if err := tunnel.Recover(); err != nil {
			return nil, fmt.Errorf("recover owned TUN devices: %w", err)
		}
		options.TunnelFactory = tunnel.Open
	}
	if options.Logger == nil {
		options.Logger = slog.Default()
	}
	ctx, cancel := context.WithCancel(parent)
	runtime := &DataPlane{identity: append(ed25519.PrivateKey{}, identity...), options: options, ctx: ctx, cancel: cancel, discoveryWake: make(chan struct{}, 1), repairWake: make(chan struct{}, 1)}
	runtime.linkState = runtime.newLinkState()
	if kernel {
		runtime.kernelEgress = enableKernelEgress(ctx)
	}
	runtime.sessions.init()
	runtime.e2e.init()
	runtime.wg.Add(4)
	go runtime.e2eLoop()
	go runtime.rerouteLoop()
	go runtime.repairLoop()
	go func() { defer runtime.wg.Done(); runtime.linkState.Run(ctx) }()
	if options.Endpoints != nil {
		runtime.wg.Add(1)
		go runtime.discover()
	}
	return runtime, nil
}
func (r *DataPlane) Apply(ctx context.Context, snapshot model.Snapshot) error {
	r.applyMu.Lock()
	defer r.applyMu.Unlock()
	if r.closed {
		return errors.New("agent runtime is closed")
	}
	if err := snapshot.Validate(snapshot.AgentID); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	previous := r.state.Load()
	if previous != nil && (previous.snapshot.AgentID != snapshot.AgentID || previous.snapshot.Revision > snapshot.Revision) {
		return errors.New("runtime identity change or revision rollback")
	}
	next := &runtimeState{snapshot: snapshot.Clone(), devices: map[model.ID]*runtimeTunnel{}, tcp: map[model.ID]*runtimeTCP{}, selfAddress: map[model.ID]netip.Addr{}}
	for _, network := range snapshot.Networks {
		next.selfAddress[network.ID] = network.Self.Address
	}
	next.keys = e2eKeys(next)
	prepared := []tunnel.Device{}
	var preparedTCP []*runtimeTCP
	type tunnelUpdate struct {
		network       model.ID
		device        *runtimeTunnel
		apply         func(tunnel.Config) error
		before, after tunnel.Config
	}
	var tunnelUpdates []tunnelUpdate
	updatedTunnels := 0
	committed := false
	newMesh := false
	gatewayChanged := false
	defer func() {
		if !committed {
			for _, tcp := range preparedTCP {
				tcp.engine.Close()
			}
			if gatewayChanged {
				if err := r.applyGateway(context.Background(), snapshot.AgentID, gatewayEntries(previous)); err != nil {
					r.options.Logger.Error("gateway rollback failed", "error", err)
				}
			}
			for i := updatedTunnels - 1; i >= 0; i-- {
				update := tunnelUpdates[i]
				if err := update.apply(update.before); err != nil {
					r.failTunnel(update.network, update.device, fmt.Errorf("rollback TUN configuration: %w", err))
				}
			}
			for _, device := range prepared {
				device.Close()
			}
			if newMesh && next.mesh != nil {
				next.mesh.Close()
			}
		}
	}()
	for _, network := range snapshot.Networks {
		cfg := tunnel.Config{Address: netip.PrefixFrom(network.Self.Address, network.CIDR.Bits()), MTU: network.MTU}
		if previous != nil {
			if old := previous.devices[network.ID]; old != nil && old.failure.Load() == nil {
				before := old.Configuration()
				if before.Address == cfg.Address && before.MTU == cfg.MTU {
					next.devices[network.ID] = old
					continue
				}
				var apply func(tunnel.Config) error
				if updater, ok := old.Device.(tunnel.Reconfigurable); ok {
					apply = updater.Reconfigure
				} else if setter, ok := old.Device.(tunnel.MTUSetter); ok && before.Address == cfg.Address {
					apply = func(c tunnel.Config) error { return setter.SetMTU(c.MTU) }
				}
				if apply != nil {
					cfg.Name = before.Name
					tunnelUpdates = append(tunnelUpdates, tunnelUpdate{network.ID, old, apply, before, cfg})
					next.devices[network.ID] = old
					continue
				}
			}
		}
		device, err := r.options.TunnelFactory(cfg)
		if err != nil {
			return fmt.Errorf("network %s: %w", network.Name, err)
		}
		prepared = append(prepared, device)
		next.devices[network.ID] = newRuntimeTunnel(device)
	}
	if previous != nil && (r.options.Embedded || previous.snapshot.ListenPort == snapshot.ListenPort) {
		next.mesh = previous.mesh
	} else {
		var err error
		port := snapshot.ListenPort
		if r.options.Embedded {
			port = 0
		}
		next.mesh, err = mesh.New(r.ctx, r.identity, r.options.BindHost, port, r.receive, r.receiveBatch)
		if err != nil {
			return fmt.Errorf("listen for peers: %w", err)
		}
		next.mesh.EnableWireGuard(r.receiveWireGuard)
		next.mesh.EnableStreams(r.acceptTCP)
		if r.options.legacyStreams {
			next.mesh.DisableResume()
		}
		next.mesh.EnableLinkState(r.linkStateHandler())
		next.mesh.EnableCompact(r.compactHeader)
		newMesh = true
	}
	forwardingSnapshot := carryLiveRoutes(snapshot, r.lastRoutes)
	router, err := forwarding.New(forwardingSnapshot, next.mesh.Send, r.deliver, forwarding.BatchOptions{Deliver: r.deliverBatch, SendOwned: next.mesh.SendOwnedBatch})
	if err != nil {
		return err
	}
	router.SetTCPIntercept(r.interceptTCP)
	router.SetTCPCarrier(next.mesh.TCPCarrier)
	router.SetEndToEnd(e2ePackets{r})
	next.router = router
	for _, network := range snapshot.Networks {
		fingerprint := tcpFingerprint(network)
		_, offload := next.devices[network.ID].Device.(tunnel.TCPPacketWriter)
		for _, peer := range network.Peers {
			if peer.Node.WireGuard != nil {
				offload = false
				break
			}
		}
		if previous != nil && previous.tcp[network.ID] != nil && previous.tcp[network.ID].fingerprint == fingerprint && previous.tcp[network.ID].offload == offload {
			next.tcp[network.ID] = previous.tcp[network.ID]
			continue
		}
		tcp, err := r.newTCP(network.ID, fingerprint, network.MTU, offload)
		if err != nil {
			return fmt.Errorf("network %s: prepare TCP access stack: %w", network.Name, err)
		}
		next.tcp[network.ID] = tcp
		preparedTCP = append(preparedTCP, tcp)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, update := range tunnelUpdates {
		if err := update.apply(update.after); err != nil {
			if errors.Is(err, tunnel.ErrUnavailable) {
				r.failTunnel(update.network, update.device, err)
			}
			return fmt.Errorf("network %s: update TUN configuration: %w", update.network, err)
		}
		updatedTunnels++
	}
	if err := r.applyGateway(ctx, snapshot.AgentID, gatewayEntries(next)); err != nil {
		return fmt.Errorf("configure gateway: %w", err)
	}
	gatewayChanged = true
	if err := next.mesh.Apply(snapshot); err != nil {
		return err
	}
	r.state.Store(next)
	r.wakeE2E()
	if linkstate.Active(snapshot) {
		// Install link-state routes with the configuration, so forwarding never
		// uses the controller's routes for a revision, even briefly.
		if update := r.linkState.Configure(snapshot); update != nil {
			start := time.Now()
			err := r.applyRoutesLocked(*update)
			r.linkState.Applied(*update, err, time.Since(start))
		}
	}
	for _, network := range snapshot.Networks {
		next.tcp[network.ID].engine.SetMTU(network.MTU)
	}
	select {
	case r.discoveryWake <- struct{}{}:
	default:
	}
	committed = true
	r.routesChanged()
	r.options.Logger.Info("configuration applied", "revision", snapshot.Revision, "networks", len(snapshot.Networks), "listen_port", snapshot.ListenPort)
	for id, device := range next.devices {
		if previous == nil || previous.devices[id] != device {
			r.wg.Add(1)
			go r.readTunnel(id, device)
		}
	}
	if previous != nil {
		if previous.mesh != next.mesh {
			previous.mesh.Close()
		}
		for id, device := range previous.devices {
			if next.devices[id] != device {
				device.Close()
			}
		}
		for id, tcp := range previous.tcp {
			if next.tcp[id] != tcp {
				tcp.engine.Close()
			}
		}
	}
	return nil
}

// applyGateway leaves host rules alone when embedded; client nodes have no
// gateway subnets.
func (r *DataPlane) applyGateway(ctx context.Context, id model.ID, entries []gateway.Entry) error {
	if r.options.Embedded {
		return nil
	}
	return r.gateway.Apply(ctx, id, entries)
}

// ErrNotConfigured is returned before the first configuration is applied.
var ErrNotConfigured = errors.New("agent runtime is not configured")

// NetworkFor returns the Network whose forwarding table can carry traffic to
// destination from this node, and this node's address in it: another node
// owns the destination and a route exists.
func (r *DataPlane) NetworkFor(destination netip.Addr) (model.ID, netip.Addr, error) {
	state := r.state.Load()
	if state == nil {
		return "", netip.Addr{}, ErrNotConfigured
	}
	var last error = forwarding.ErrDestination
	for _, n := range state.snapshot.Networks {
		_, local, err := state.router.NextHop(n.ID, destination)
		if err == nil && !local {
			return n.ID, n.Self.Address, nil
		}
		if err != nil && !errors.Is(err, forwarding.ErrDestination) {
			last = err
		}
	}
	return "", netip.Addr{}, last
}

func (r *DataPlane) Report() []model.LinkStatus {
	state := r.state.Load()
	if state == nil {
		return nil
	}
	return state.mesh.Report()
}

// Counters reports data-plane event totals.
func (r *DataPlane) Counters() map[string]uint64 {
	state := r.state.Load()
	if state == nil {
		return nil
	}
	counters := state.mesh.Counters()
	for k, v := range r.sessionCounters() {
		counters[k] = v
	}
	return counters
}
func (r *DataPlane) Close() error {
	r.applyMu.Lock()
	if r.closed {
		r.applyMu.Unlock()
		return nil
	}
	r.closed = true
	r.cancel()
	state := r.state.Swap(nil)
	var gatewayErr error
	if !r.options.Embedded {
		gatewayErr = r.gateway.Close()
	}
	if r.kernelEgress {
		disableKernelEgress(context.Background())
	}
	if gatewayErr != nil {
		r.options.Logger.Error("gateway cleanup failed", "error", gatewayErr)
	}
	r.applyMu.Unlock()
	if state != nil {
		for _, device := range state.devices {
			device.Close()
		}
		state.mesh.Close()
		for _, tcp := range state.tcp {
			tcp.engine.Close()
		}
	}
	r.wg.Wait()
	return gatewayErr
}
func (r *DataPlane) readTunnel(network model.ID, device *runtimeTunnel) {
	defer r.wg.Done()
	if batch, ok := device.Device.(tunnel.BatchDevice); ok {
		r.readTunnelBatch(network, device, batch)
		return
	}
	buffer := make([]byte, packet.MaxPayload+1)
	for {
		n, err := device.Read(buffer)
		if err == nil && n == 0 {
			err = io.ErrNoProgress
		}
		if err != nil {
			r.failTunnel(network, device, err)
			return
		}
		state := r.state.Load()
		if state == nil || state.devices[network] != device {
			continue
		}
		// Invalid, unroutable or congested packets are dropped independently; a bad
		// packet cannot terminate the interface forwarding loop.
		r.accessPacket(state, r.ctx, network, buffer[:n], false)
	}
}

// compactHeader expands compact Link frames against the active forwarding
// table; frames arriving before the first table is published are dropped.
func (r *DataPlane) compactHeader(header []byte, network [16]byte, hopLimit uint8, payload []byte) bool {
	state := r.state.Load()
	return state != nil && state.router.CompactHeader(header, network, hopLimit, payload)
}

func (r *DataPlane) receive(ctx context.Context, remote model.ID, frame []byte) error {
	state := r.state.Load()
	if state == nil {
		return errors.New("agent runtime is not configured")
	}
	return state.router.FromPeer(ctx, remote, frame)
}
func (r *DataPlane) deliver(ctx context.Context, network model.ID, raw []byte) error {
	state := r.state.Load()
	if state == nil {
		return errors.New("agent runtime is not configured")
	}
	if r.replayRequest(state, network, raw) || r.e2eRequest(state, network, raw) {
		return nil
	}
	device := state.devices[network]
	if device == nil {
		return forwarding.ErrNetwork
	}
	if device.failure.Load() != nil {
		return tunnel.ErrUnavailable
	}
	n, err := device.Write(raw)
	if errors.Is(err, tunnel.ErrUnavailable) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
		r.failTunnel(network, device, err)
	}
	if err == nil && n != len(raw) {
		return io.ErrShortWrite
	}
	return err
}

func (r *DataPlane) readTunnelBatch(network model.ID, device *runtimeTunnel, batch tunnel.BatchDevice) {
	buffers := make([][]byte, batch.BatchSize())
	sizes := make([]int, len(buffers))
	segmentSizes := make([]int, len(buffers))
	packets := make([][]byte, len(buffers))
	owners := make([]*stack.PacketBuffer, len(buffers))
	releaseOwners := func() {
		for i, owner := range owners {
			if owner != nil {
				owner.DecRef()
				owners[i] = nil
			}
		}
	}
	defer releaseOwners()
	read := func() (int, error) { return batch.ReadBatch(buffers, sizes) }
	for i := range buffers {
		buffers[i] = make([]byte, packet.MaxPayload+1)
	}
	if offload, ok := device.Device.(tunnel.OffloadReader); ok {
		// A single kernel TCP GSO packet can hold up to 64 KiB. UDP still
		// fills the ordinary MTU-sized buffers with independent segments.
		buffers[0] = make([]byte, 65535)
		read = func() (int, error) { return offload.ReadOffloadBatch(buffers, sizes, segmentSizes) }
	}
	if owned, ok := device.Device.(tunnel.OwnedOffloadReader); ok {
		read = func() (int, error) { return owned.ReadOwnedOffloadBatch(buffers, sizes, segmentSizes, owners) }
	}
	for {
		n, err := read()
		if err == nil && n == 0 {
			err = io.ErrNoProgress
		}
		if err != nil {
			r.failTunnel(network, device, err)
			return
		}
		state := r.state.Load()
		if state == nil || state.devices[network] != device {
			releaseOwners()
			continue
		}
		for i := range n {
			packets[i] = buffers[i][:sizes[i]]
		}
		// TCP goes to the local stack when its next Edge carries streams; other
		// TCP is forwarded as packets. Consecutive datagrams stay batched.
		start := 0
		for i, raw := range packets[:n] {
			if !packet.IsTCP(raw) {
				continue
			}
			if start < i {
				state.router.FromTunnelBatch(r.ctx, network, packets[start:i])
			}
			start = i + 1
			admitted := state.router.TCPIngress(network, raw, false) == nil
			if segmentSizes[i] > 0 {
				admitted = state.router.TCPIngressGSO(network, raw, segmentSizes[i]) == nil
			}
			if !admitted {
				continue
			}
			if r.captureTCP(state, network, raw, "") {
				if owners[i] != nil {
					state.tcp[network].engine.InjectOwned(owners[i])
					owners[i] = nil
				} else {
					state.tcp[network].engine.Inject(raw)
				}
				continue
			}
			// Owned reads may keep the kernel's partial checksum.
			r.forwardTCP(state, network, raw, segmentSizes[i], segmentSizes[i] == 0 && owners[i] == nil)
		}
		if start < n {
			state.router.FromTunnelBatch(r.ctx, network, packets[start:n])
		}
		clear(packets[:n])
		releaseOwners()
		if n > 1 {
			// A nonblocking TUN can supply consecutive bursts indefinitely.
			// Let notified packet writers drain before another input quantum,
			// especially when the Agent has only one runnable processor. One
			// yield is not enough: every 61st schedule takes the global queue,
			// where Gosched put this goroutine, before the local writers.
			runtime.Gosched()
			runtime.Gosched()
		}
	}
}
func (r *DataPlane) receiveBatch(ctx context.Context, remote model.ID, owners []*packetbuf.Buffer) error {
	state := r.state.Load()
	if state == nil {
		packetbuf.ReleaseAll(owners)
		return errors.New("agent runtime is not configured")
	}
	return state.router.FromPeerOwnedBatch(ctx, remote, owners)
}
func (r *DataPlane) deliverBatch(ctx context.Context, network model.ID, packets [][]byte) error {
	state := r.state.Load()
	if state == nil {
		return errors.New("agent runtime is not configured")
	}
	// Replay requests and end-to-end handshakes of this Agent's TCP sessions
	// never reach the TUN.
	var kept [][]byte
	for i, raw := range packets {
		if r.replayRequest(state, network, raw) || r.e2eRequest(state, network, raw) {
			if kept == nil {
				kept = append(make([][]byte, 0, len(packets)), packets[:i]...)
			}
		} else if kept != nil {
			kept = append(kept, raw)
		}
	}
	if kept != nil {
		if packets = kept; len(packets) == 0 {
			return nil
		}
	}
	device := state.devices[network]
	if device == nil {
		return forwarding.ErrNetwork
	}
	if device.failure.Load() != nil {
		return tunnel.ErrUnavailable
	}
	batch, ok := device.Device.(tunnel.BatchDevice)
	if !ok {
		var result error
		for _, raw := range packets {
			result = errors.Join(result, r.deliver(ctx, network, raw))
		}
		return result
	}
	err := batch.WriteBatch(packets)
	if errors.Is(err, tunnel.ErrUnavailable) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
		r.failTunnel(network, device, err)
	}
	return err
}

func (r *DataPlane) receiveWireGuard(network model.ID, raw []byte) {
	state := r.state.Load()
	if state != nil {
		_ = r.accessPacket(state, r.ctx, network, raw, true)
	}
}
