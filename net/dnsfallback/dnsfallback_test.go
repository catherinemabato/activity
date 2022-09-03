// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnsfallback

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"tailscale.com/tailcfg"
)

func TestGetDERPMap(t *testing.T) {
	dm := getDERPMap()
	if dm == nil {
		t.Fatal("nil")
	}
	if len(dm.Regions) == 0 {
		t.Fatal("no regions")
	}
}

func TestCache(t *testing.T) {
	cacheFile := filepath.Join(t.TempDir(), "cache.json")

	// Write initial cache value
	initialCache := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			99: {
				RegionID:   99,
				RegionCode: "test",
				RegionName: "Testville",
				Nodes: []*tailcfg.DERPNode{{
					Name:     "99a",
					RegionID: 99,
					HostName: "derp99a.tailscale.com",
					IPv4:     "1.2.3.4",
				}},
			},

			// Intentionally attempt to "overwrite" something
			1: {
				RegionID:   1,
				RegionCode: "r1",
				RegionName: "r1",
				Nodes: []*tailcfg.DERPNode{{
					Name:     "1c",
					RegionID: 1,
					HostName: "derp1c.tailscale.com",
					IPv4:     "127.0.0.1",
					IPv6:     "::1",
				}},
			},
		},
	}
	d, err := json.Marshal(initialCache)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cacheFile, d, 0666); err != nil {
		t.Fatal(err)
	}

	// Clear any existing cached DERP map(s)
	cachedDERPMap.Store(nil)

	// Load the cache
	SetCachePath(cacheFile)
	if cm := cachedDERPMap.Load(); !reflect.DeepEqual(initialCache, cm) {
		t.Fatalf("cached map was %+v; want %+v", cm, initialCache)
	}

	// Verify that our DERP map is merged with the cache.
	dm := getDERPMap()
	region, ok := dm.Regions[99]
	if !ok {
		t.Fatal("expected region 99")
	}
	if !reflect.DeepEqual(region, initialCache.Regions[99]) {
		t.Fatalf("region 99: got %+v; want %+v", region, initialCache.Regions[99])
	}

	// Verify that our cache can't override a statically-baked-in DERP server.
	n0 := dm.Regions[1].Nodes[0]
	if n0.IPv4 == "127.0.0.1" || n0.IPv6 == "::1" {
		t.Errorf("got %+v; expected no overwrite for node", n0)
	}

	// Also, make sure that the static DERP map still has the same first
	// node as when this test was last written/updated; this ensures that
	// we don't accidentally start allowing overwrites due to some of the
	// test's assumptions changing out from underneath us as we update the
	// JSON file of fallback servers.
	if getStaticDERPMap().Regions[1].Nodes[0].HostName != "derp1c.tailscale.com" {
		t.Errorf("DERP server has a different name; please update this test")
	}
}

func TestCacheUnchanged(t *testing.T) {
	cacheFile := filepath.Join(t.TempDir(), "cache.json")

	// Write initial cache value
	initialCache := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			99: {
				RegionID:   99,
				RegionCode: "test",
				RegionName: "Testville",
				Nodes: []*tailcfg.DERPNode{{
					Name:     "99a",
					RegionID: 99,
					HostName: "derp99a.tailscale.com",
					IPv4:     "1.2.3.4",
				}},
			},
		},
	}
	d, err := json.Marshal(initialCache)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cacheFile, d, 0666); err != nil {
		t.Fatal(err)
	}

	// Clear any existing cached DERP map(s)
	cachedDERPMap.Store(nil)

	// Load the cache
	SetCachePath(cacheFile)
	if cm := cachedDERPMap.Load(); !reflect.DeepEqual(initialCache, cm) {
		t.Fatalf("cached map was %+v; want %+v", cm, initialCache)
	}

	// Remove the cache file on-disk, then re-set to the current value. If
	// our equality comparison is working, we won't rewrite the file
	// on-disk since the cached value won't have changed.
	if err := os.Remove(cacheFile); err != nil {
		t.Fatal(err)
	}

	UpdateCache(initialCache)
	if _, err := os.Stat(cacheFile); !os.IsNotExist(err) {
		t.Fatalf("got err=%v; expected to not find cache file", err)
	}

	// Now, update the cache with something slightly different and verify
	// that we did re-write the file on-disk.
	updatedCache := &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			99: {
				RegionID:   99,
				RegionCode: "test",
				RegionName: "Testville",
				Nodes:      []*tailcfg.DERPNode{ /* set below */ },
			},
		},
	}
	clonedNode := *initialCache.Regions[99].Nodes[0]
	clonedNode.IPv4 = "1.2.3.5"
	updatedCache.Regions[99].Nodes = append(updatedCache.Regions[99].Nodes, &clonedNode)

	UpdateCache(updatedCache)
	if st, err := os.Stat(cacheFile); err != nil {
		t.Fatalf("could not stat cache file; err=%v", err)
	} else if !st.Mode().IsRegular() || st.Size() == 0 {
		t.Fatalf("didn't find non-empty regular file; mode=%v size=%d", st.Mode(), st.Size())
	}
}
