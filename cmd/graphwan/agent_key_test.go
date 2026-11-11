package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/eWloYW8/GraphWAN/internal/model"
)

// A key exported from a data directory, then given in the environment, keeps
// the Agent's identity.
func TestAgentKeyFromEnvironment(t *testing.T) {
	data := t.TempDir()
	t.Setenv(agentPrivateKeyEnv, "")
	cache, explicit, err := openAgentCache(data)
	if err != nil || explicit {
		t.Fatalf("open without a key: explicit=%v, %v", explicit, err)
	}
	exported := model.EncodeAgentPrivateKey(cache.PrivateKey())
	public := cache.PublicKey()
	cache.Close()

	t.Setenv(agentPrivateKeyEnv, exported+"\n")
	cache, explicit, err = openAgentCache(data)
	if err != nil || !explicit {
		t.Fatalf("open with the exported key: explicit=%v, %v", explicit, err)
	}
	if !cache.PublicKey().Equal(public) {
		t.Fatal("exported key changed the identity")
	}
	cache.Close()

	_, other, _ := ed25519.GenerateKey(rand.Reader)
	t.Setenv(agentPrivateKeyEnv, model.EncodeAgentPrivateKey(other))
	cache, _, err = openAgentCache(data)
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	if !bytes.Equal(cache.PrivateKey(), other) {
		t.Fatal("configured key is not the identity")
	}

	t.Setenv(agentPrivateKeyEnv, "not-a-key")
	if _, _, err := openAgentCache(t.TempDir()); err == nil {
		t.Fatal("malformed key accepted")
	}
}
