// Package client embeds a GraphWAN client node in another application, for
// example as an outbound of a proxy client. The application hands it
// connections to IP destinations; the client sends them into the GraphWAN
// network, which routes them.
//
// A client node is a full Agent on the network side: it connects to the
// controller, discovers and reports its endpoints, and reaches its peers with
// every transport, including NAT hole punching. It differs from an Agent only
// in what the embedding application does not need: it has no TUN interface
// (connections live in a user-space stack), manages no host routes or gateway
// rules, accepts no inbound connections, and never carries other nodes'
// traffic. The controller marks its node as a client.
package client

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/agent"
	"github.com/eWloYW8/GraphWAN/internal/forwarding"
	"github.com/eWloYW8/GraphWAN/internal/model"
	"github.com/eWloYW8/GraphWAN/internal/sockets"
	"github.com/eWloYW8/GraphWAN/internal/tunnel"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

type Config struct {
	// Server is the controller's HTTPS origin.
	Server string
	// ServerTransport is the controller carrier: tcp (default), websocket,
	// grpc, wss, or https for a TLS-terminating gateway.
	ServerTransport string
	// CA is the controller CA in PEM. Empty trusts the system roots, as for a
	// gateway with a public certificate.
	CA []byte
	// PrivateKey is the node identity. The controller knows its public key,
	// registered by an operator or by enrollment.
	PrivateKey ed25519.PrivateKey
	// StateDir keeps the last configuration and controller directory across
	// restarts. Empty uses a temporary directory removed by Close.
	StateDir string
	// Control is applied to every socket the client opens, after its own
	// options; Lookup resolves every name it dials. The embedding application
	// passes the options of its own outbound connections here, so the
	// client's sockets do not loop back into the application.
	Control func(network, address string, c syscall.RawConn) error
	Lookup  func(ctx context.Context, network, host string) ([]netip.Addr, error)
	Logger  *slog.Logger
}

// ErrUnreachable means the network has no route to a destination.
var ErrUnreachable = errors.New("graphwan: destination is not reachable in the network")

type Client struct {
	ctx     context.Context
	cancel  context.CancelFunc
	cache   *agent.Cache
	runtime *agent.DataPlane
	control *agent.Client
	done    chan struct{}
	temp    string
	mu      sync.Mutex
	stacks  map[netip.Addr]*netstack
}

// Start connects the client node. It returns once the node is running; the
// first configuration may still be on its way, which DialTCP waits for.
func Start(ctx context.Context, cfg Config) (*Client, error) {
	if len(cfg.PrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("graphwan: invalid private key")
	}
	if cfg.ServerTransport == "" {
		cfg.ServerTransport = "tcp"
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if len(cfg.CA) > 0 {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(cfg.CA) {
			return nil, errors.New("graphwan: CA contains no certificates")
		}
	}
	c := &Client{stacks: map[netip.Addr]*netstack{}, done: make(chan struct{})}
	dir := cfg.StateDir
	if dir == "" {
		if dir, err = os.MkdirTemp("", "graphwan-client-"); err != nil {
			return nil, err
		}
		c.temp = dir
	}
	if c.cache, err = agent.OpenCacheWithKey(filepath.Join(dir, "agent.db"), cfg.PrivateKey); err != nil {
		c.removeTemp()
		return nil, fmt.Errorf("graphwan: open state: %w", err)
	}
	c.ctx, c.cancel = context.WithCancel(sockets.With(context.WithoutCancel(ctx), sockets.Hooks{Control: cfg.Control, Lookup: cfg.Lookup}))
	var control *agent.Client
	c.runtime, err = agent.NewDataPlane(c.ctx, cfg.PrivateKey, agent.DataPlaneOptions{
		TunnelFactory: c.newStack,
		Embedded:      true,
		Logger:        cfg.Logger,
		Endpoints: func(endpoints []model.Endpoint) error {
			if control == nil {
				return nil
			}
			return control.SetEndpoints(endpoints)
		},
	})
	if err != nil {
		c.cancel()
		c.cache.Close()
		c.removeTemp()
		return nil, err
	}
	control, err = agent.NewClient(c.cache, c.runtime, agent.Options{Server: cfg.Server, ServerTransport: cfg.ServerTransport, Roots: roots, Version: "client", Logger: cfg.Logger})
	if err != nil {
		c.runtime.Close()
		c.cancel()
		c.cache.Close()
		c.removeTemp()
		return nil, err
	}
	c.control = control
	go func() {
		defer close(c.done)
		// An Agent process exits on a registration error and its service
		// manager restarts it. Nothing restarts an embedded node, so retry
		// here: the controller may be briefly unreachable, or the key not yet
		// registered.
		delay := time.Second
		for {
			err := control.Run(c.ctx)
			if c.ctx.Err() != nil {
				return
			}
			cfg.Logger.Warn("graphwan client node restarting", "error", err, "retry_in", delay)
			select {
			case <-c.ctx.Done():
				return
			case <-time.After(delay):
			}
			delay = min(2*delay, time.Minute)
		}
	}()
	return c, nil
}

func (c *Client) newStack(config tunnel.Config) (tunnel.Device, error) {
	n, err := newNetstack(config)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.stacks[config.Address.Addr()] = n
	c.mu.Unlock()
	return &trackedStack{netstack: n, client: c}, nil
}

// trackedStack forgets its stack when the data plane closes it.
type trackedStack struct {
	*netstack
	client *Client
}

func (t *trackedStack) Close() error {
	t.client.mu.Lock()
	if t.client.stacks[t.address()] == t.netstack {
		delete(t.client.stacks, t.address())
	}
	t.client.mu.Unlock()
	return t.netstack.Close()
}

// route waits for the configuration that routes destination, and returns the
// stack of that Network.
func (c *Client) route(ctx context.Context, destination netip.Addr) (*netstack, error) {
	delay := 10 * time.Millisecond
	for {
		_, local, err := c.runtime.NetworkFor(destination.Unmap())
		if err == nil {
			c.mu.Lock()
			n := c.stacks[local]
			c.mu.Unlock()
			if n != nil {
				return n, nil
			}
		} else if !errors.Is(err, agent.ErrNotConfigured) && !errors.Is(err, forwarding.ErrUnreachable) {
			// No node owns the destination: fail at once so the application
			// can choose another way. A missing route is waited for, as
			// routes converge after start and after Link changes.
			return nil, fmt.Errorf("%w: %s: %v", ErrUnreachable, destination, err)
		}
		select {
		case <-ctx.Done():
			if err == nil {
				err = ctx.Err()
			}
			return nil, fmt.Errorf("graphwan: waiting for a route to %s: %w", destination, err)
		case <-c.ctx.Done():
			return nil, net.ErrClosed
		case <-time.After(delay):
		}
		delay = min(2*delay, 250*time.Millisecond)
	}
}

// DialTCP connects to destination through the network.
func (c *Client) DialTCP(ctx context.Context, destination netip.AddrPort) (net.Conn, error) {
	destination = netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port())
	n, err := c.route(ctx, destination.Addr())
	if err != nil {
		return nil, err
	}
	if n.address().Is4() != destination.Addr().Is4() {
		return nil, fmt.Errorf("%w: %s is not in the network's address family", ErrUnreachable, destination)
	}
	return gonet.DialContextTCP(ctx, n.stack, fullAddress(destination), n.protocol())
}

// ListenUDP returns an unconnected UDP socket in the Network that routes
// destination. It can send to and receive from any address of that Network.
func (c *Client) ListenUDP(ctx context.Context, destination netip.Addr) (net.PacketConn, error) {
	destination = destination.Unmap()
	n, err := c.route(ctx, destination)
	if err != nil {
		return nil, err
	}
	if n.address().Is4() != destination.Is4() {
		return nil, fmt.Errorf("%w: %s is not in the network's address family", ErrUnreachable, destination)
	}
	conn, err := gonet.DialUDP(n.stack, nil, nil, n.protocol())
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// Close disconnects the node and releases its state.
func (c *Client) Close() error {
	c.cancel()
	<-c.done
	err := c.runtime.Close()
	c.control.Close()
	err = errors.Join(err, c.cache.Close())
	c.removeTemp()
	return err
}

func (c *Client) removeTemp() {
	if c.temp != "" {
		os.RemoveAll(c.temp)
	}
}
