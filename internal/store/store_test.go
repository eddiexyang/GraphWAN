package store_test

import (
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/store"
	"github.com/eddiexyang/graphnet/internal/testutil"
	bolt "go.etcd.io/bbolt"
)

func TestDurabilityAndRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	got, err := db.Update(0, func(s *model.State) error { *s = testutil.Topology(); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if got.Revision != 1 {
		t.Fatal("callback was allowed to override revision")
	}
	_, err = db.Update(1, func(s *model.State) error { s.Networks[0].Edges[0].Weight = 0; return nil })
	if err == nil {
		t.Fatal("committed invalid configuration")
	}
	sentinel := errors.New("failed change")
	_, err = db.Update(1, func(s *model.State) error { s.Networks = nil; return sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	if _, err := db.Update(0, func(s *model.State) error { return nil }); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale edit: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	state, err := db.Read()
	if err != nil {
		t.Fatal(err)
	}
	if state.Revision != 1 || len(state.Networks) != 1 || state.Networks[0].Edges[0].Weight != 10 {
		t.Fatalf("rollback/restart lost state: %+v", state)
	}
}
func TestConcurrentEditors(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var wg sync.WaitGroup
	var winners atomic.Int32
	for i := 0; i < 16; i++ {
		wg.Go(func() {
			_, err := db.Update(0, func(s *model.State) error { return nil })
			if err == nil {
				winners.Add(1)
			} else if !errors.Is(err, store.ErrConflict) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("successful edits=%d", winners.Load())
	}
}

// A state stored under the bucket of the previous name opens unchanged.
func TestOpenMovesPreviousBucket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	want, err := db.Update(0, func(s *model.State) error { *s = testutil.Topology(); return nil })
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	raw, err := bolt.Open(path, 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.Update(func(tx *bolt.Tx) error {
		state := tx.Bucket([]byte("graphnet"))
		old, err := tx.CreateBucket([]byte("graphwan"))
		if err != nil {
			return err
		}
		if err := state.ForEach(old.Put); err != nil {
			return err
		}
		return tx.DeleteBucket([]byte("graphnet"))
	}); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	if db, err = store.Open(path); err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	got, err := db.Read()
	if err != nil || got.Revision != want.Revision || len(got.Networks) != len(want.Networks) {
		t.Fatalf("moved state %d networks at revision %d, want %d at %d: %v", len(got.Networks), got.Revision, len(want.Networks), want.Revision, err)
	}
}
