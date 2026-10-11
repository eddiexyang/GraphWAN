package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/eWloYW8/GraphWAN/internal/linkstate"
)

const linkStateFile = "linkstate.json"

// writeLinkState keeps the Agent's routing view in its data directory for
// `graphwan agent status`, without opening a local control port.
func writeLinkState(ctx context.Context, dir string, view func() linkstate.View) {
	path := filepath.Join(dir, linkStateFile)
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		if raw, err := json.MarshalIndent(struct {
			Written time.Time `json:"written"`
			linkstate.View
		}{time.Now(), view()}, "", "  "); err == nil {
			tmp := path + ".tmp"
			if os.WriteFile(tmp, raw, 0o600) == nil {
				os.Rename(tmp, path)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func runAgentStatus(args []string) error {
	fs := flag.NewFlagSet("agent status", flag.ContinueOnError)
	data := fs.String("data-dir", "./graphwan-agent-data", "agent data directory")
	lsdb := fs.Bool("lsdb", false, "show the link-state database and edge checks")
	routes := fs.Bool("routes", false, "show the computed forwarding table")
	events := fs.Bool("events", false, "show recent link-state events")
	raw := fs.Bool("json", false, "print the complete state as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	content, err := os.ReadFile(filepath.Join(*data, linkStateFile))
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("no link-state status: the Agent is not running or does not route locally")
	}
	if err != nil {
		return err
	}
	if *raw {
		_, err = os.Stdout.Write(append(content, '\n'))
		return err
	}
	var s struct {
		Written time.Time `json:"written"`
		linkstate.View
	}
	if err := json.Unmarshal(content, &s); err != nil {
		return err
	}
	all := !*lsdb && !*routes && !*events
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	defer w.Flush()
	fmt.Fprintf(w, "revision %d, written %s ago\n", s.Revision, time.Since(s.Written).Round(time.Second))
	for k, v := range s.Counters {
		fmt.Fprintf(w, "%s\t%d\n", k, v)
	}
	for _, n := range s.Networks {
		fmt.Fprintf(w, "\nnetwork %s, self %s, sequence %d, local up: %s\n", n.ID, n.Self, n.Sequence, strings.Join(ids(n.Local), " "))
		if all || *lsdb {
			fmt.Fprintln(w, "ORIGIN\tSEQUENCE\tREVISION\tAGE\tUP EDGES")
			for _, o := range n.Database {
				fmt.Fprintf(w, "%s\t%d\t%d\t%s\t%s\n", o.Origin, o.Sequence, o.Revision, time.Duration(o.AgeMS)*time.Millisecond, strings.Join(ids(o.Up), " "))
			}
			fmt.Fprintln(w, "\nEDGE\tA\tREPORT\tB\tREPORT\tUSABLE")
			for _, e := range n.Edges {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%v\n", e.ID, e.A, e.ReportA, e.B, e.ReportB, e.Usable)
			}
		}
		if all || *routes {
			fmt.Fprintln(w, "\nDESTINATION\tNEXT HOP\tCOST")
			for _, r := range n.Routes {
				fmt.Fprintf(w, "%s\t%s\t%d\n", r.Destination, r.NextHop, r.Cost)
			}
		}
	}
	if all || *events {
		fmt.Fprintln(w, "\nTIME\tEVENT\tNETWORK\tORIGIN\tEDGE\tVALUE")
		for _, e := range s.Events {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\n", e.At.Format(time.RFC3339Nano), e.Kind, e.Network, e.Origin, e.Edge, e.Value)
		}
	}
	return nil
}

func ids[T ~string](list []T) []string {
	out := make([]string, len(list))
	for i, v := range list {
		out[i] = string(v)
	}
	return out
}
