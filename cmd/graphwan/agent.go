package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/eWloYW8/GraphWAN/internal/agent"
	"github.com/eWloYW8/GraphWAN/internal/model"
)

// agentGCPercent is the Agent's heap growth target unless GOGC sets one.
const agentGCPercent = 25

func runAgent(args []string) error {
	if len(args) > 0 && args[0] == "service" {
		return runManagedService("agent", args[1:])
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runAgentContext(ctx, args)
}

func runAgentContext(parent context.Context, args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "update":
			return runAgentUpdate(args[1:])
		case "install-wintun":
			return runInstallWintun(parent, args[1:])
		case "enroll":
			return runAgentEnroll(args[1:])
		case "status":
			return runAgentStatus(args[1:])
		case "key":
			return runAgentKey(args[1:])
		case "genkey":
			return runAgentGenkey(args[1:])
		case "run":
			args = args[1:]
		}
	}
	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	server := fs.String("server", "", "preferred controller HTTPS origin; cached directory provides failover")
	defaultTransport := os.Getenv("GRAPHWAN_SERVER_TRANSPORT")
	if defaultTransport == "" {
		defaultTransport = "tcp"
	}
	serverTransport := fs.String("server-transport", defaultTransport, "preferred controller carrier: tcp, websocket, grpc, wss or https (TLS-terminating gateway)")
	data := fs.String("data-dir", "./graphwan-agent-data", "private persistent agent directory")
	name := fs.String("name", "", "agent display name for first enrollment")
	ca := fs.String("ca", "", "PEM CA certificate to trust for controller HTTPS")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *name == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return err
		}
		*name = hostname
	}
	cache, explicit, err := openAgentCache(*data)
	if err != nil {
		return err
	}
	defer cache.Close()
	reg, err := cache.Registration()
	if err != nil {
		return err
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if reg != nil && len(reg.CA) > 0 {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(reg.CA) {
			return errors.New("invalid cached CA")
		}
	} else if *ca != "" {
		raw, err := os.ReadFile(*ca)
		if err != nil {
			return err
		}
		if !roots.AppendCertsFromPEM(raw) {
			return errors.New("CA file contains no certificates")
		}
	}
	if reg == nil && *server == "" {
		return errors.New("first start requires --server (enrollment or registration by public key)")
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	if os.Getenv("GOGC") == "" {
		// The heap is mostly packet buffers, which hold no pointers and cost
		// the collector little: a smaller growth target keeps the memory the
		// Agent takes from the host near what it holds.
		debug.SetGCPercent(agentGCPercent)
	}
	if err := prepareAgentPlatform(ctx); err != nil {
		return err
	}
	var client *agent.Client
	runtime, err := agent.NewDataPlane(ctx, cache.PrivateKey(), agent.DataPlaneOptions{Endpoints: func(endpoints []model.Endpoint) error {
		if client == nil {
			return nil
		}
		return client.SetEndpoints(endpoints)
	}})
	if err != nil {
		return err
	}
	defer runtime.Close()
	go writeLinkState(ctx, *data, runtime.LinkState)
	updater, err := managedUpdater(ctx, *data)
	if err != nil {
		return err
	}
	token := os.Getenv("GRAPHWAN_ENROLLMENT_TOKEN")
	if explicit {
		// An Agent given its key registers by public key alone.
		token = ""
	}
	client, err = agent.NewClient(cache, runtime, agent.Options{Updater: updater, Server: *server, ServerTransport: *serverTransport, Name: *name, EnrollmentToken: token, Roots: roots, Version: version})
	if err != nil {
		return err
	}
	defer client.Close()
	if err := client.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("agent: %w", err)
	}
	return nil
}

// runAgentEnroll reads invitations from stdin/files/environment so secrets need
// not appear in process arguments. Explicit file input takes precedence over env.
func runAgentEnroll(args []string) error {
	fs := flag.NewFlagSet("agent enroll", flag.ContinueOnError)
	file := fs.String("invitation-file", "", "invitation file, or - for stdin (default: GRAPHWAN_AGENT_INVITATION)")
	data := fs.String("data-dir", "./graphwan-agent-data", "private persistent agent directory")
	name := fs.String("name", "", "agent name (default: hostname)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return errors.New("unexpected positional arguments")
	}
	raw := os.Getenv("GRAPHWAN_AGENT_INVITATION")
	if *file != "" {
		var reader io.Reader = os.Stdin
		if *file != "-" {
			f, err := os.Open(*file)
			if err != nil {
				return err
			}
			defer f.Close()
			reader = f
		}
		b, err := io.ReadAll(io.LimitReader(reader, model.MaxEnrollmentInvitation+1))
		if err != nil {
			return err
		}
		raw = string(b)
	}
	if strings.TrimSpace(raw) == "" {
		return errors.New("provide --invitation-file PATH, --invitation-file - for stdin, or GRAPHWAN_AGENT_INVITATION")
	}
	invite, err := model.ParseAgentInvitation(raw)
	if err != nil {
		return err
	}
	if *name == "" {
		*name, err = os.Hostname()
		if err != nil {
			return err
		}
	}
	cache, _, err := openAgentCache(*data)
	if err != nil {
		return err
	}
	defer cache.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	reg, err := agent.Enroll(ctx, cache, invite, *name)
	if err != nil {
		return err
	}
	fmt.Printf("Agent registered: %s\nData directory: %s\n", reg.AgentID, *data)
	return nil
}

// agentPrivateKeyEnv holds an Agent's private key. It is the Agent's identity;
// the data directory then only caches state for it.
const agentPrivateKeyEnv = "GRAPHWAN_PRIVATE_KEY"

// openAgentCache opens the data directory's cache for the key in
// agentPrivateKeyEnv, or for the identity the cache keeps when it is unset.
func openAgentCache(data string) (cache *agent.Cache, explicit bool, err error) {
	path := filepath.Join(data, "agent.db")
	text := strings.TrimSpace(os.Getenv(agentPrivateKeyEnv))
	if text == "" {
		cache, err = agent.OpenCache(path)
		return cache, false, err
	}
	key, ok := model.ParseAgentPrivateKey(text)
	if !ok {
		return nil, false, errors.New(agentPrivateKeyEnv + " is not a base64 Ed25519 private key")
	}
	cache, err = agent.OpenCacheWithKey(path, key)
	return cache, true, err
}

// runAgentKey prints the Agent's public key, creating its identity on first
// use. An operator registers this key on the controller instead of enrolling.
// With --export-private it prints the private key instead, to move an identity
// the data directory created into agentPrivateKeyEnv.
func runAgentKey(args []string) error {
	fs := flag.NewFlagSet("agent key", flag.ContinueOnError)
	data := fs.String("data-dir", "./graphwan-agent-data", "private persistent agent directory")
	private := fs.Bool("export-private", false, "print the private key instead of the public key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return errors.New("unexpected positional arguments")
	}
	cache, _, err := openAgentCache(*data)
	if err != nil {
		return err
	}
	defer cache.Close()
	if *private {
		fmt.Println(model.EncodeAgentPrivateKey(cache.PrivateKey()))
		return nil
	}
	fmt.Println(model.EncodeAgentKey(cache.PublicKey()))
	return nil
}

// runAgentGenkey prints a new private key for agentPrivateKeyEnv.
func runAgentGenkey(args []string) error {
	if len(args) != 0 {
		return errors.New("unexpected arguments")
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	fmt.Println(model.EncodeAgentPrivateKey(key))
	return nil
}
