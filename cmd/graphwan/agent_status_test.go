package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/linkstate"
	"github.com/eWloYW8/GraphWAN/internal/model"
)

func TestAgentStatusPrintsLinkState(t *testing.T) {
	dir := t.TempDir()
	view := linkstate.View{Revision: 7, Counters: map[string]uint64{"lsa_sent": 3}, Networks: []linkstate.NetworkView{{
		ID: "net", Self: "a", Sequence: 9, Local: []model.ID{"e1"},
		Database: []linkstate.OriginView{{Origin: "b", Sequence: 4, Revision: 7, AgeMS: 1500, Up: []model.ID{"e1"}}},
		Edges:    []linkstate.EdgeView{{ID: "e1", A: "a", B: "b", ReportA: "up", ReportB: "up", Usable: true}},
		Routes:   []model.Route{{Destination: "b", NextHop: "b", Cost: 10}},
	}}}
	ctx, cancel := context.WithCancel(context.Background())
	go writeLinkState(ctx, dir, func() linkstate.View { return view })
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, linkStateFile)); err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	out := capture(t, func() error { return runAgentStatus([]string{"--data-dir", dir}) })
	for _, want := range []string{"revision 7", "lsa_sent", "ORIGIN", "b  ", "EDGE", "true", "DESTINATION", "10"} {
		if !strings.Contains(out, want) {
			t.Fatalf("status output lacks %q:\n%s", want, out)
		}
	}
}

func capture(t *testing.T, run func() error) string {
	t.Helper()
	r, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w
	err := run()
	w.Close()
	os.Stdout = stdout
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(r)
	return string(raw)
}
