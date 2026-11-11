package agent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"

	"github.com/eWloYW8/GraphWAN/internal/model"
)

// A key kept in configuration is the Agent's identity: the cache keeps its
// state while the key stays, and is cleared when the key changes, as when the
// Agent moves to another identity.
func TestCacheFollowsConfiguredKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.db")
	_, first, _ := ed25519.GenerateKey(rand.Reader)
	_, second, _ := ed25519.GenerateKey(rand.Reader)
	open := func(key ed25519.PrivateKey) *Cache {
		t.Helper()
		cache, err := OpenCacheWithKey(path, key)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(cache.PrivateKey(), key) {
			t.Fatal("cache does not use the configured key")
		}
		return cache
	}
	cache := open(first)
	reg := Registration{CA: []byte("ca"), AgentID: model.NewID(), Server: "https://127.0.0.1:8443"}
	if err := cache.SaveRegistration(reg); err != nil {
		t.Fatal(err)
	}
	cache.Close()

	cache = open(first)
	if got, err := cache.Registration(); err != nil || got == nil || got.AgentID != reg.AgentID {
		t.Fatalf("registration under the same key = %+v, %v", got, err)
	}
	cache.Close()

	cache = open(second)
	if got, err := cache.Registration(); err != nil || got != nil {
		t.Fatalf("registration after the key changed = %+v, %v", got, err)
	}
	cache.Close()

	cache, err := OpenCache(path)
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	if !bytes.Equal(cache.PrivateKey(), second) {
		t.Fatal("cache did not keep the configured key")
	}
}

func TestAgentPrivateKeyText(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	got, ok := model.ParseAgentPrivateKey(model.EncodeAgentPrivateKey(key))
	if !ok || !bytes.Equal(got, key) {
		t.Fatal("private key does not survive its text form")
	}
	if _, ok := model.ParseAgentPrivateKey("not-a-key"); ok {
		t.Fatal("malformed private key accepted")
	}
}
