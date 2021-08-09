// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package portmapper

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"inet.af/netaddr"
	"tailscale.com/types/logger"
)

func TestCreateOrGetMapping(t *testing.T) {
	if v, _ := strconv.ParseBool(os.Getenv("HIT_NETWORK")); !v {
		t.Skip("skipping test without HIT_NETWORK=1")
	}
	c := NewClient(t.Logf, nil)
	defer c.Close()
	c.SetLocalPort(1234)
	for i := 0; i < 2; i++ {
		if i > 0 {
			time.Sleep(100 * time.Millisecond)
		}
		ext, err := c.createOrGetMapping(context.Background())
		t.Logf("Got: %v, %v", ext, err)
	}
}

func TestClientProbe(t *testing.T) {
	if v, _ := strconv.ParseBool(os.Getenv("HIT_NETWORK")); !v {
		t.Skip("skipping test without HIT_NETWORK=1")
	}
	c := NewClient(t.Logf, nil)
	defer c.Close()
	for i := 0; i < 3; i++ {
		if i > 0 {
			time.Sleep(100 * time.Millisecond)
		}
		res, err := c.Probe(context.Background())
		t.Logf("Got(t=%dms): %+v, %v", i*100, res, err)
	}
}

func TestClientProbeThenMap(t *testing.T) {
	if v, _ := strconv.ParseBool(os.Getenv("HIT_NETWORK")); !v {
		t.Skip("skipping test without HIT_NETWORK=1")
	}
	c := NewClient(t.Logf, nil)
	defer c.Close()
	c.SetLocalPort(1234)
	res, err := c.Probe(context.Background())
	t.Logf("Probe: %+v, %v", res, err)
	ext, err := c.createOrGetMapping(context.Background())
	t.Logf("createOrGetMapping: %v, %v", ext, err)
}

func TestProbeIntegration(t *testing.T) {
	igd, err := NewTestIGD()
	if err != nil {
		t.Fatal(err)
	}
	defer igd.Close()

	logf := t.Logf
	var c *Client
	c = NewClient(logger.WithPrefix(logf, "portmapper: "), func() {
		logf("portmapping changed.")
		logf("have mapping: %v", c.HaveMapping())
	})

	c.SetGatewayLookupFunc(func() (gw, self netaddr.IP, ok bool) {
		return netaddr.IP{}, netaddr.IPv4(1, 2, 3, 4), true
	})

	res, err := c.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	t.Logf("Probe: %+v", res)
	t.Logf("IGD stats: %+v", igd.stats())
	// TODO(bradfitz): finish
	if !res.UPnP {
		t.Errorf("did not detect UPnP from IGD network")
	}
}
