// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package store

import (
	"path/filepath"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/ipn/store/storetest"
	"tailscale.com/tstest"
	"tailscale.com/types/logger"
)

func TestNewStore(t *testing.T) {
	regOnce.Do(registerDefaultStores)
	t.Cleanup(func() {
		knownStores = map[string]Provider{}
		registerDefaultStores()
	})
	knownStores = map[string]Provider{}

	type store1 struct {
		ipn.StateStore
		path string
	}

	type store2 struct {
		ipn.StateStore
		path string
	}

	Register("arn:", func(_ logger.Logf, path string) (ipn.StateStore, error) {
		return &store1{new(mem.Store), path}, nil
	})
	Register("kube:", func(_ logger.Logf, path string) (ipn.StateStore, error) {
		return &store2{new(mem.Store), path}, nil
	})
	Register("mem:", func(_ logger.Logf, path string) (ipn.StateStore, error) {
		return new(mem.Store), nil
	})

	path := "mem:abcd"
	if s, err := New(t.Logf, path); err != nil {
		t.Fatalf("%q: %v", path, err)
	} else if _, ok := s.(*mem.Store); !ok {
		t.Fatalf("%q: got: %T, want: %T", path, s, new(mem.Store))
	}

	path = "arn:foo"
	if s, err := New(t.Logf, path); err != nil {
		t.Fatalf("%q: %v", path, err)
	} else if _, ok := s.(*store1); !ok {
		t.Fatalf("%q: got: %T, want: %T", path, s, new(store1))
	}

	path = "kube:abcd"
	if s, err := New(t.Logf, path); err != nil {
		t.Fatalf("%q: %v", path, err)
	} else if _, ok := s.(*store2); !ok {
		t.Fatalf("%q: got: %T, want: %T", path, s, new(store2))
	}

	path = filepath.Join(t.TempDir(), "state")
	if s, err := New(t.Logf, path); err != nil {
		t.Fatalf("%q: %v", path, err)
	} else if _, ok := s.(*FileStore); !ok {
		t.Fatalf("%q: got: %T, want: %T", path, s, new(FileStore))
	}
}
func TestMemoryStore(t *testing.T) {
	tstest.PanicOnLog()

	store := new(mem.Store)
	storetest.TestStoreSemantics(t, store)
}

func TestFileStore(t *testing.T) {
	tstest.PanicOnLog()

	dir := t.TempDir()
	path := filepath.Join(dir, "test-file-store.conf")

	store, err := NewFileStore(nil, path)
	if err != nil {
		t.Fatalf("creating file store failed: %v", err)
	}

	storetest.TestStoreSemantics(t, store)

	// Build a brand new file store and check that both IDs written
	// above are still there.
	store, err = NewFileStore(nil, path)
	if err != nil {
		t.Fatalf("creating second file store failed: %v", err)
	}

	expected := map[ipn.StateKey]string{
		"foo": "bar",
		"baz": "quux",
	}
	for key, want := range expected {
		bs, err := store.ReadState(key)
		if err != nil {
			t.Errorf("reading %q (2nd store): %v", key, err)
			continue
		}
		if string(bs) != want {
			t.Errorf("reading %q (2nd store): got %q, want %q", key, bs, want)
		}
	}
}
