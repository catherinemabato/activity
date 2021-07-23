// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !ios
// (https://github.com/tailscale/tailscale/issues/2495)

package portmapper

import (
	"context"
	"fmt"
	"math/rand"
	"net/url"
	"sync"
	"time"

	"github.com/tailscale/goupnp/dcps/internetgateway2"
	"inet.af/netaddr"
	"tailscale.com/control/controlknobs"
)

// References:
//
// WANIP Connection v2: http://upnp.org/specs/gw/UPnP-gw-WANIPConnection-v2-Service.pdf

// upnpMapping is a port mapping over the upnp protocol. After being created it is immutable,
// but the client field may be shared across mapping instances.
type upnpMapping struct {
	gw         netaddr.IP
	external   netaddr.IPPort
	internal   netaddr.IPPort
	goodUntil  time.Time
	renewAfter time.Time

	// client is a connection to a upnp device, and may be reused across different UPnP mappings.
	client upnpClient
}

func (u *upnpMapping) GoodUntil() time.Time     { return u.goodUntil }
func (u *upnpMapping) RenewAfter() time.Time    { return u.renewAfter }
func (u *upnpMapping) External() netaddr.IPPort { return u.external }
func (u *upnpMapping) Release(ctx context.Context) {
	u.client.DeletePortMapping(ctx, "", u.external.Port(), "udp")
}

// upnpClient is an interface over the multiple different clients exported by goupnp,
// exposing the functions we need for portmapping. They are auto-generated from XML-specs.
type upnpClient interface {
	AddPortMapping(
		ctx context.Context,

		// remoteHost is the remote device sending packets to this device, in the format of x.x.x.x.
		// The empty string, "", means any host out on the internet can send packets in.
		remoteHost string,

		// externalPort is the exposed port of this port mapping. Visible during NAT operations.
		// 0 will let the router select the port, but there is an additional call,
		// `AddAnyPortMapping`, which is available on 1 of the 3 possible protocols,
		// which should be used if available. See `addAnyPortMapping` below, which calls this if
		// `AddAnyPortMapping` is not supported.
		externalPort uint16,

		// protocol is whether this is over TCP or UDP. Either "tcp" or "udp".
		protocol string,

		// internalPort is the port that the gateway device forwards the traffic to.
		internalPort uint16,
		// internalClient is the IP address that packets will be forwarded to for this mapping.
		// Internal client is of the form "x.x.x.x".
		internalClient string,

		// enabled is whether this portmapping should be enabled or disabled.
		enabled bool,
		// portMappingDescription is a user-readable description of this portmapping.
		portMappingDescription string,
		// leaseDurationSec is the duration of this portmapping. The value of this argument must be
		// greater than 0. From the spec, it appears if it is set to 0, it will switch to using
		// 604800 seconds, but not sure why this is desired. The recommended time is 3600 seconds.
		leaseDurationSec uint32,
	) (err error)

	DeletePortMapping(ctx context.Context, remoteHost string, externalPort uint16, protocol string) error
	GetExternalIPAddress(ctx context.Context) (externalIPAddress string, err error)
}

// tsPortMappingDesc gets sent to UPnP clients as a human-readable label for the portmapping.
// It is not used for anything other than labelling.
const tsPortMappingDesc = "tailscale-portmap"

// addAnyPortMapping abstracts over different UPnP client connections, calling the available
// AddAnyPortMapping call if available for WAN IP connection v2, otherwise defaulting to the old
// behavior of calling AddPortMapping with port = 0 to specify a wildcard port.
// It returns the new external port (which may not be identical to the external port specified),
// or an error.
func addAnyPortMapping(
	ctx context.Context,
	upnp upnpClient,
	externalPort uint16,
	internalPort uint16,
	internalClient string,
	leaseDuration time.Duration,
) (newPort uint16, err error) {
	if upnp, ok := upnp.(*internetgateway2.WANIPConnection2); ok {
		return upnp.AddAnyPortMapping(
			ctx,
			"",
			externalPort,
			"udp",
			internalPort,
			internalClient,
			true,
			tsPortMappingDesc,
			uint32(leaseDuration.Seconds()),
		)
	}
	for externalPort == 0 {
		externalPort = uint16(rand.Intn(65535))
	}
	err = upnp.AddPortMapping(
		ctx,
		"",
		externalPort,
		"udp",
		internalPort,
		internalClient,
		true,
		tsPortMappingDesc,
		uint32(leaseDuration.Seconds()),
	)
	return externalPort, err
}

var (
	// discoClients is a long-lived channel for attempting to connect to upnp clients which were
	// discovered after getUPnPClient timed out. Since there are 3 different possible
	// connection types, 3 was selected for an arbitrary buffer size. Additional clients from later
	// calls get dropped.
	discoClients = make(chan upnpClient, 3)
	// discoDuration is the permitted duration for discovery.
	discoDuration = 3 * time.Second
	// timeBetweenDisco is the period between uPnP discovery attempts.
	// It may be necessary to re-attempt disco if the network changes,
	// and TODO(jknodt) it may be worthwhile to cache the last network seen and only run when that
	// changes.
	timeBetweenDisco = 5 * time.Minute

	mu sync.Mutex
	// lastDiscoTime is the last time upnp discovery was run, and dictates when the next discovery
	// attempt should be started, according to timeBetweenDisco. Guarded by mu.
	lastDiscoTime time.Time
)

func DisableDiscovery() {
	lastDiscoTime = time.Date(2050, 0, 0, 0, 0, 0, 0, time.UTC)
}

func tryWriteDiscoUPnPClient(c upnpClient) {
	select {
	case discoClients <- c:
	default:
	}
}

// getUPnPClients gets a client for interfacing with UPnP, ignoring the underlying protocol for
// now.
// Adapted from https://github.com/huin/goupnp/blob/master/GUIDE.md.
func getUPnPClient(ctx context.Context, gw netaddr.IP) (upnpClient, error) {
	if controlknobs.DisableUPnP() {
		return nil, nil
	}

	discoverUPnPServices(context.Background())

	ctx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	// Attempt to connect over the multiple available connection types concurrently,
	// returning the fastest.

	// TODO(jknodt): this url seems super brittle? maybe discovery is better but this is faster.
	// It appears that some routers will put it on different ports, maybe useful to cache the most
	// recent seen port?
	u, err := url.Parse(fmt.Sprintf("http://%s:5000/rootDesc.xml", gw))
	if err != nil {
		return nil, err
	}

	clients := make(chan upnpClient, 3)
	go func() {
		var err error
		ip1Clients, err := internetgateway2.NewWANIPConnection1ClientsByURL(ctx, u)
		if err == nil && len(ip1Clients) > 0 {
			clients <- ip1Clients[0]
		}
	}()
	go func() {
		ip2Clients, err := internetgateway2.NewWANIPConnection2ClientsByURL(ctx, u)
		if err == nil && len(ip2Clients) > 0 {
			clients <- ip2Clients[0]
		}
	}()
	go func() {
		ppp1Clients, err := internetgateway2.NewWANPPPConnection1ClientsByURL(ctx, u)
		if err == nil && len(ppp1Clients) > 0 {
			clients <- ppp1Clients[0]
		}
	}()

	for {
		select {
		case oldClient := <-discoClients:
			// Attempt to call the client to see if it's still alive.
			if _, err := oldClient.GetExternalIPAddress(ctx); err != nil {
				continue
			}
			return oldClient, nil
		case client := <-clients:
			return client, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func discoverUPnPServices(ctx context.Context) {
	mu.Lock()
	defer mu.Unlock()
	now := time.Now()
	if lastDiscoTime.After(now.Add(-timeBetweenDisco)) {
		return
	}
	lastDiscoTime = now

	ctx, cancel := context.WithTimeout(ctx, discoDuration)
	go func() {
		var err error
		ip1Clients, _, err := internetgateway2.NewWANIPConnection1Clients(ctx)
		if err == nil && len(ip1Clients) > 0 {
			tryWriteDiscoUPnPClient(ip1Clients[0])
		}
	}()
	go func() {
		ip2Clients, _, err := internetgateway2.NewWANIPConnection2Clients(ctx)
		if err == nil && len(ip2Clients) > 0 {
			tryWriteDiscoUPnPClient(ip2Clients[0])
		}
	}()
	go func() {
		ppp1Clients, _, err := internetgateway2.NewWANPPPConnection1Clients(ctx)
		if err == nil && len(ppp1Clients) > 0 {
			tryWriteDiscoUPnPClient(ppp1Clients[0])
		}
	}()
	time.AfterFunc(discoDuration, cancel)
}

// getUPnPPortMapping attempts to create a port-mapping over the UPnP protocol. On success,
// it will return the externally exposed IP and port. Otherwise, it will return a zeroed IP and
// port and an error.
func (c *Client) getUPnPPortMapping(
	ctx context.Context,
	gw netaddr.IP,
	internal netaddr.IPPort,
	prevPort uint16,
) (external netaddr.IPPort, ok bool) {
	if controlknobs.DisableUPnP() {
		return netaddr.IPPort{}, false
	}
	now := time.Now()
	upnp := &upnpMapping{
		gw:       gw,
		internal: internal,
	}

	var client upnpClient
	var err error
	c.mu.Lock()
	oldMapping, ok := c.mapping.(*upnpMapping)
	c.mu.Unlock()
	if ok && oldMapping != nil {
		client = oldMapping.client
	} else {
		client, err = getUPnPClient(ctx, gw)
		if err != nil {
			return netaddr.IPPort{}, false
		}
	}
	if client == nil {
		return netaddr.IPPort{}, false
	}

	var newPort uint16
	newPort, err = addAnyPortMapping(
		ctx,
		client,
		prevPort,
		internal.Port(),
		internal.IP().String(),
		time.Second*pmpMapLifetimeSec,
	)
	if err != nil {
		return netaddr.IPPort{}, false
	}
	// TODO cache this ip somewhere?
	extIP, err := client.GetExternalIPAddress(ctx)
	if err != nil {
		// TODO this doesn't seem right
		return netaddr.IPPort{}, false
	}
	externalIP, err := netaddr.ParseIP(extIP)
	if err != nil {
		return netaddr.IPPort{}, false
	}

	upnp.external = netaddr.IPPortFrom(externalIP, newPort)
	d := time.Duration(pmpMapLifetimeSec) * time.Second
	upnp.goodUntil = now.Add(d)
	upnp.renewAfter = now.Add(d / 2)
	upnp.client = client
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mapping = upnp
	c.localPort = newPort
	return upnp.external, true
}
