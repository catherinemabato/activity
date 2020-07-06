// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !android

package monitor

import (
	"fmt"
	"net"
	"time"

	"github.com/jsimonetti/rtnetlink"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
	"inet.af/netaddr"
	"tailscale.com/types/logger"
)

// nlConn wraps a *netlink.Conn and returns a monitor.Message
// instead of a netlink.Message. Currently, messages are discarded,
// but down the line, when messages trigger different logic depending
// on the type of event, this provides the capability of handling
// each architecture-specific message in a generic fashion.
type nlConn struct {
	logf     logger.Logf
	conn     *netlink.Conn
	buffered []netlink.Message
}

func newOSMon(logf logger.Logf) (osMon, error) {
	conn, err := netlink.Dial(unix.NETLINK_ROUTE, &netlink.Config{
		// IPv4 address and route changes. Routes get us most of the
		// events of interest, but we need address as well to cover
		// things like DHCP deciding to give us a new address upon
		// renewal - routing wouldn't change, but all reachability
		// would.
		Groups: unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV4_ROUTE,
	})
	if err != nil {
		return nil, fmt.Errorf("dialing netlink socket: %v", err)
	}
	return &nlConn{logf: logf, conn: conn}, nil
}

func (c *nlConn) Close() error {
	c.conn.SetDeadline(time.Unix(0, 0)) // abort any Receive in flight
	return c.conn.Close()
}

func (c *nlConn) Receive() (message, error) {
	if len(c.buffered) == 0 {
		var err error
		c.buffered, err = c.conn.Receive()
		if err != nil {
			return nil, err
		}
		if len(c.buffered) == 0 {
			// Unexpected. Not seen in wild, but sleep defensively.
			time.Sleep(time.Second)
			return nil, nil
		}
	}
	msg := c.buffered[0]
	c.buffered = c.buffered[1:]

	// See https://github.com/torvalds/linux/blob/master/include/uapi/linux/rtnetlink.h
	// And https://man7.org/linux/man-pages/man7/rtnetlink.7.html
	const (
		RTM_NEWADDR  = 20
		RTM_NEWROUTE = 24
	)
	switch msg.Header.Type {
	case RTM_NEWADDR:
		var rmsg rtnetlink.AddressMessage
		if err := rmsg.UnmarshalBinary(msg.Data); err != nil {
			c.logf("RTM_NEWADDR: failed to parse: %v", err)
			return nil, nil
		}
		c.logf("Address: %+v", rmsg)
		return &newAddrMessage{
			Label: rmsg.Attributes.Label,
			Addr:  netaddrIP(rmsg.Attributes.Local),
		}, nil
	case RTM_NEWROUTE:
		var rmsg rtnetlink.RouteMessage
		if err := rmsg.UnmarshalBinary(msg.Data); err != nil {
			c.logf("RTM_NEWROUTE: failed to parse: %v", err)
			return nil, nil
		}
		return &newRouteMessage{
			Table:   rmsg.Table,
			Src:     netaddrIP(rmsg.Attributes.Src),
			Dst:     netaddrIP(rmsg.Attributes.Dst),
			Gateway: netaddrIP(rmsg.Attributes.Gateway),
		}, nil
	default:
		c.logf("netlink msg %+v, %q", msg.Header, msg.Data)
		return nil, nil
	}
}

func netaddrIP(std net.IP) netaddr.IP {
	ip, _ := netaddr.FromStdIP(std)
	return ip
}
