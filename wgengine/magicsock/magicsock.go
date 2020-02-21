// Copyright 2019 Tailscale & AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package magicsock implements a socket that can change its communication path while
// in use, actively searching for the best way to communicate.
package magicsock

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/wgcfg"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/stun"
	"tailscale.com/stunner"
	"tailscale.com/types/key"
)

// A Conn routes UDP packets and actively manages a list of its endpoints.
// It implements wireguard/device.Bind.
type Conn struct {
	pconn         *RebindingUDPConn
	pconnPort     uint16
	privateKey    key.Private
	stunServers   []string
	startEpUpdate chan struct{} // send to trigger endpoint update
	epFunc        func(endpoints []string)
	logf          func(format string, args ...interface{})
	donec         chan struct{} // closed on Conn.Close

	epUpdateCtx    context.Context // endpoint updater context
	epUpdateCancel func()          // the func to cancel epUpdateCtx

	// indexedAddrs is a map of every remote ip:port to a priority
	// list of endpoint addresses for a peer.
	// The priority list is provided by wgengine configuration.
	//
	// Given a wgcfg describing:
	//	machineA: 10.0.0.1:1, 10.0.0.2:2
	//	machineB: 10.0.0.3:3
	// the indexedAddrs map contains:
	//	10.0.0.1:1 -> [10.0.0.1:1, 10.0.0.2:2], index:0
	//	10.0.0.2:2 -> [10.0.0.1:1, 10.0.0.2:2], index:1
	//	10.0.0.3:3 -> [10.0.0.3:3],             index:0
	indexedAddrsMu sync.Mutex
	indexedAddrs   map[udpAddr]indexedAddrSet

	// stunReceiveFunc holds the current STUN packet processing func.
	// Its Loaded value is always non-nil.
	stunReceiveFunc atomic.Value // of func(p []byte, fromAddr *net.UDPAddr)

	udpRecvCh  chan udpReadResult
	derpRecvCh chan derpReadResult

	derpMu      sync.Mutex
	derpConn    map[int]*derphttp.Client // magic derp port (see derpmap.go) to its client
	derpWriteCh map[int]chan<- derpWriteRequest
}

// udpAddr is the key in the indexedAddrs map.
// It maps an ip:port onto an indexedAddr.
type udpAddr struct {
	ip   wgcfg.IP
	port uint16
}

// indexedAddrSet is an AddrSet (a priority list of ip:ports for a peer and the
// current favored ip:port for communicating with the peer) and an index
// number saying which element of the priority list is this map entry.
type indexedAddrSet struct {
	addr  *AddrSet
	index int // index of map key in addr.Addrs
}

// DefaultPort is the default port to listen on.
// The current default (zero) means to auto-select a random free port.
const DefaultPort = 0

var DefaultSTUN = []string{
	"stun.l.google.com:19302",
	"stun3.l.google.com:19302",
}

// Options contains options for Listen.
type Options struct {
	// Port is the port to listen on.
	// Zero means to pick one automatically.
	Port uint16

	STUN []string

	// EndpointsFunc optionally provides a func to be called when
	// endpoints change. The called func does not own the slice.
	EndpointsFunc func(endpoint []string)
}

func (o *Options) endpointsFunc() func([]string) {
	if o == nil || o.EndpointsFunc == nil {
		return func([]string) {}
	}
	return o.EndpointsFunc
}

// Listen creates a magic Conn listening on opts.Port.
// As the set of possible endpoints for a Conn changes, the
// callback opts.EndpointsFunc is called.
func Listen(opts Options) (*Conn, error) {
	var packetConn net.PacketConn
	var err error
	if opts.Port == 0 {
		// Our choice of port. Start with DefaultPort.
		// If unavailable, pick any port.
		want := fmt.Sprintf(":%d", DefaultPort)
		log.Printf("magicsock: bind: trying %v\n", want)
		packetConn, err = net.ListenPacket("udp4", want)
		if err != nil {
			want = ":0"
			log.Printf("magicsock: bind: falling back to %v (%v)\n", want, err)
			packetConn, err = net.ListenPacket("udp4", want)
		}
	} else {
		packetConn, err = net.ListenPacket("udp4", fmt.Sprintf(":%d", opts.Port))
	}
	if err != nil {
		return nil, fmt.Errorf("magicsock.Listen: %v", err)
	}

	epUpdateCtx, epUpdateCancel := context.WithCancel(context.Background())
	c := &Conn{
		pconn:          new(RebindingUDPConn),
		pconnPort:      opts.Port,
		donec:          make(chan struct{}),
		stunServers:    append([]string{}, opts.STUN...),
		startEpUpdate:  make(chan struct{}, 1),
		epUpdateCtx:    epUpdateCtx,
		epUpdateCancel: epUpdateCancel,
		epFunc:         opts.endpointsFunc(),
		logf:           log.Printf,
		indexedAddrs:   make(map[udpAddr]indexedAddrSet),
		derpRecvCh:     make(chan derpReadResult),
		udpRecvCh:      make(chan udpReadResult),
	}
	c.ignoreSTUNPackets()
	c.pconn.Reset(packetConn.(*net.UDPConn))
	c.reSTUN()
	go c.epUpdate(epUpdateCtx)
	return c, nil
}

// ignoreSTUNPackets sets a STUN packet processing func that does nothing.
func (c *Conn) ignoreSTUNPackets() {
	c.stunReceiveFunc.Store(func([]byte, *net.UDPAddr) {})
}

// epUpdate runs in its own goroutine until ctx is shut down.
// Whenever c.startEpUpdate receives a value, it starts an
// STUN endpoint lookup.
func (c *Conn) epUpdate(ctx context.Context) {
	var lastEndpoints []string
	var lastCancel func()
	var lastDone chan struct{}
	for {
		select {
		case <-ctx.Done():
			if lastCancel != nil {
				lastCancel()
			}
			return
		case <-c.startEpUpdate:
		}

		if lastCancel != nil {
			lastCancel()
			<-lastDone
		}
		var epCtx context.Context
		epCtx, lastCancel = context.WithCancel(ctx)
		lastDone = make(chan struct{})

		go func() {
			defer close(lastDone)
			endpoints, err := c.determineEndpoints(epCtx)
			if err != nil {
				c.logf("magicsock.Conn: endpoint update failed: %v", err)
				// TODO(crawshaw): are there any conditions under which
				// we should trigger a retry based on the error here?
				return
			}
			if stringsEqual(endpoints, lastEndpoints) {
				return
			}
			lastEndpoints = endpoints
			c.epFunc(endpoints)
		}()
	}
}

// determineEndpoints returns the machine's endpoint addresses. It
// does a STUN lookup to determine its public address.
func (c *Conn) determineEndpoints(ctx context.Context) ([]string, error) {
	var (
		alreadyMu sync.Mutex
		already   = make(map[string]bool) // endpoint -> true
	)
	var eps []string // unique endpoints

	addAddr := func(s, reason string) {
		log.Printf("magicsock: found local %s (%s)\n", s, reason)

		alreadyMu.Lock()
		defer alreadyMu.Unlock()
		if !already[s] {
			already[s] = true
			eps = append(eps, s)
		}
	}

	s := &stunner.Stunner{
		Send:     c.pconn.WriteTo,
		Endpoint: func(s string) { addAddr(s, "stun") },
		Servers:  c.stunServers,
		Logf:     c.logf,
	}

	c.stunReceiveFunc.Store(s.Receive)

	if err := s.Run(ctx); err != nil {
		return nil, err
	}

	c.ignoreSTUNPackets()

	if localAddr := c.pconn.LocalAddr(); localAddr.IP.IsUnspecified() {
		localPort := fmt.Sprintf("%d", localAddr.Port)
		loopbacks, err := localAddresses(localPort, func(s string) {
			addAddr(s, "localAddresses")
		})
		if err != nil {
			return nil, err
		}
		if len(eps) == 0 {
			// Only include loopback addresses if we have no
			// interfaces at all to use as endpoints. This allows
			// for localhost testing when you're on a plane and
			// offline, for example.
			for _, s := range loopbacks {
				addAddr(s, "loopback")
			}
		}
	} else {
		// Our local endpoint is bound to a particular address.
		// Do not offer addresses on other local interfaces.
		addAddr(localAddr.String(), "socket")
	}

	// Note: the endpoints are intentionally returned in priority order,
	// from "farthest but most reliable" to "closest but least
	// reliable." Addresses returned from STUN should be globally
	// addressable, but might go farther on the network than necessary.
	// Local interface addresses might have lower latency, but not be
	// globally addressable.
	//
	// The STUN address(es) are always first so that legacy wireguard
	// can use eps[0] as its only known endpoint address (although that's
	// obviously non-ideal).
	return eps, nil
}

func stringsEqual(x, y []string) bool {
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func localAddresses(localPort string, addAddr func(s string)) ([]string, error) {
	var loopback []string

	// TODO(crawshaw): don't serve interface addresses that we are routing
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, i := range ifaces {
		if (i.Flags & net.FlagUp) == 0 {
			// Down interfaces don't count
			continue
		}
		ifcIsLoopback := (i.Flags & net.FlagLoopback) != 0

		addrs, err := i.Addrs()
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			switch v := a.(type) {
			case *net.IPNet:
				// TODO(crawshaw): IPv6 support.
				// Easy to do here, but we need good endpoint ordering logic.
				ip := v.IP.To4()
				if ip == nil {
					continue
				}
				// TODO(apenwarr): don't special case cgNAT.
				// In the general wireguard case, it might
				// very well be something we can route to
				// directly, because both nodes are
				// behind the same CGNAT router.
				if cgNAT.Contains(ip) {
					continue
				}
				if linkLocalIPv4.Contains(ip) {
					continue
				}
				ep := net.JoinHostPort(ip.String(), localPort)
				if ip.IsLoopback() || ifcIsLoopback {
					loopback = append(loopback, ep)
					continue
				}
				addAddr(ep)
			}
		}
	}
	return loopback, nil
}

var cgNAT = func() *net.IPNet {
	_, ipNet, err := net.ParseCIDR("100.64.0.0/10")
	if err != nil {
		panic(err)
	}
	return ipNet
}()

var linkLocalIPv4 = func() *net.IPNet {
	_, ipNet, err := net.ParseCIDR("169.254.0.0/16")
	if err != nil {
		panic(err)
	}
	return ipNet
}()

func (c *Conn) LocalPort() uint16 {
	laddr := c.pconn.LocalAddr()
	return uint16(laddr.Port)
}

func shouldSprayPacket(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	msgType := binary.LittleEndian.Uint32(b[:4])
	switch msgType {
	case device.MessageInitiationType,
		device.MessageResponseType,
		device.MessageCookieReplyType: // TODO: necessary?
		return true
	}
	return false
}

// appendDests appends to dsts the destinations that b should be
// written to in order to reach as. Some of the returned UDPAddrs may
// be fake addrs representing DERP servers.
//
// It also returns as's current roamAddr, if any.
func appendDests(dsts []*net.UDPAddr, as *AddrSet, b []byte) (_ []*net.UDPAddr, roamAddr *net.UDPAddr) {
	spray := shouldSprayPacket(b)

	as.mu.Lock()
	defer as.mu.Unlock()

	roamAddr = as.roamAddr
	if roamAddr != nil {
		dsts = append(dsts, roamAddr)
		if !spray {
			return dsts, roamAddr
		}
	}
	for i := len(as.addrs) - 1; i >= 0; i-- {
		addr := &as.addrs[i]
		if spray || as.curAddr == -1 || as.curAddr == i {
			dsts = append(dsts, addr)
		}
		if !spray && len(dsts) != 0 {
			break
		}
	}
	log.Printf("spray=%v; roam=%v; dests=%v", spray, roamAddr, dsts)
	return dsts, roamAddr
}

var errNoDestinations = errors.New("magicsock: no destinations")

func (c *Conn) Send(b []byte, ep device.Endpoint) error {
	as := ep.(*AddrSet)

	var addrBuf [8]*net.UDPAddr
	dsts, roamAddr := appendDests(addrBuf[:0], as, b)

	if len(dsts) == 0 {
		return errNoDestinations
	}

	var success bool
	var ret error
	for _, addr := range dsts {
		err := c.sendAddr(addr, as.publicKey, b)
		if err == nil {
			success = true
		} else if ret == nil {
			ret = err
		}
		if err != nil && addr != roamAddr {
			log.Printf("magicsock: Conn.Send(%v): %v", addr, err)
		}
	}
	if success {
		return nil
	}
	return ret
}

var errConnClosed = errors.New("Conn closed")

var errDropDerpPacket = errors.New("too many DERP packets queued; dropping")

// sendAddr sends packet b to addr, which is either a real UDP address
// or a fake UDP address representing a DERP server (see derpmap.go).
// The provided public key identifies the recipient.
func (c *Conn) sendAddr(addr *net.UDPAddr, pubKey key.Public, b []byte) error {
	if ch := c.derpWriteChanOfAddr(addr); ch != nil {
		errc := make(chan error, 1)
		select {
		case <-c.donec:
			return errConnClosed
		case ch <- derpWriteRequest{addr, pubKey, b, errc}:
			select {
			case <-c.donec:
				return errConnClosed
			case err := <-errc:
				return err // usually nil
			}
		default:
			// Too many writes queued. Drop packet.
			return errDropDerpPacket
		}
	}
	_, err := c.pconn.WriteTo(b, addr)
	return err
}

// bufferedDerpWritesBeforeDrop is how many packets writes can be
// queued up the DERP client to write on the wire before we start
// dropping.
//
// TODO: this is currently arbitrary. Figure out something better?
const bufferedDerpWritesBeforeDrop = 4

// derpWriteChanOfAddr returns a DERP client for fake UDP addresses that
// represent DERP servers, creating them as necessary. For real UDP
// addresses, it returns nil.
func (c *Conn) derpWriteChanOfAddr(addr *net.UDPAddr) chan<- derpWriteRequest {
	if !addr.IP.Equal(derpMagicIP) {
		return nil
	}
	c.derpMu.Lock()
	defer c.derpMu.Unlock()
	ch, ok := c.derpWriteCh[addr.Port]
	if !ok {
		if c.derpWriteCh == nil {
			c.derpWriteCh = make(map[int]chan<- derpWriteRequest)
			c.derpConn = make(map[int]*derphttp.Client)
		}
		host := derpHost(addr.Port)
		dc, err := derphttp.NewClient(c.privateKey, "https://"+host+"/derp", log.Printf)
		if err != nil {
			log.Printf("derphttp.NewClient: port %d, host %q invalid? err: %v", addr.Port, host, err)
			return nil
		}

		bidiCh := make(chan derpWriteRequest, bufferedDerpWritesBeforeDrop)
		ch = bidiCh
		c.derpConn[addr.Port] = dc
		c.derpWriteCh[addr.Port] = ch
		go c.runDerpReader(addr, dc)
		go c.runDerpWriter(addr, dc, bidiCh)
	}
	return ch
}

// derpReadResult is the type sent by runDerpClient to ReceiveIPv4
// when a DERP packet is available.
type derpReadResult struct {
	derpAddr *net.UDPAddr
	n        int // length of data received

	// copyBuf is called to copy the data to dst.  It returns how
	// much data was copied, which will be n if dst is large
	// enough.
	copyBuf func(dst []byte) int
}

// runDerpReader runs in a goroutine for the life of a DERP
// connection, handling received packets.
func (c *Conn) runDerpReader(derpFakeAddr *net.UDPAddr, dc *derphttp.Client) {
	didCopy := make(chan struct{}, 1)
	var buf [derp.MaxPacketSize]byte
	var bufValid int // bytes in buf that are valid
	copyFn := func(dst []byte) int {
		n := copy(dst, buf[:bufValid])
		didCopy <- struct{}{}
		return n
	}

	for {
		msg, err := dc.Recv(buf[:])
		if err != nil {
			if err == derphttp.ErrClientClosed {
				return
			}
			select {
			case <-c.donec:
				return
			default:
			}
			log.Printf("derp.Recv: %v", err)
			time.Sleep(250 * time.Millisecond)
			continue
		}
		switch m := msg.(type) {
		case derp.ReceivedPacket:
			bufValid = len(m)
		default:
			// Ignore.
			// TODO: handle endpoint notification messages.
			continue
		}
		log.Printf("got derp %v packet: %q", derpFakeAddr, buf[:bufValid])
		select {
		case <-c.donec:
			return
		case c.derpRecvCh <- derpReadResult{derpFakeAddr, bufValid, copyFn}:
			<-didCopy
		}
	}
}

type derpWriteRequest struct {
	addr   *net.UDPAddr
	pubKey key.Public
	b      []byte
	errc   chan<- error
}

// runDerpWriter runs in a goroutine for the life of a DERP
// connection, handling received packets.
func (c *Conn) runDerpWriter(derpFakeAddr *net.UDPAddr, dc *derphttp.Client, ch <-chan derpWriteRequest) {
	for {
		select {
		case <-c.donec:
			return
		case wr := <-ch:
			err := dc.Send(wr.pubKey, wr.b)
			if err != nil {
				log.Printf("magicsock: derp.Send(%v): %v", wr.addr, err)
			}
			select {
			case wr.errc <- err:
			case <-c.donec:
				return
			}
		}
	}
}

func (c *Conn) findIndexedAddrSet(addr *net.UDPAddr) (addrSet *AddrSet, index int) {
	var epAddr udpAddr
	copy(epAddr.ip.Addr[:], addr.IP.To16())
	epAddr.port = uint16(addr.Port)

	c.indexedAddrsMu.Lock()
	defer c.indexedAddrsMu.Unlock()

	indAddr := c.indexedAddrs[epAddr]
	if indAddr.addr == nil {
		return nil, 0
	}
	return indAddr.addr, indAddr.index
}

type udpReadResult struct {
	n    int
	err  error
	addr *net.UDPAddr
}

// aLongTimeAgo is a non-zero time, far in the past, used for
// immediate cancellation of network operations.
var aLongTimeAgo = time.Unix(233431200, 0)

func (c *Conn) ReceiveIPv4(b []byte) (n int, ep device.Endpoint, addr *net.UDPAddr, err error) {
	go func() {
		// Read a packet, and process any STUN packets before returning.
		for {
			var pAddr net.Addr
			n, pAddr, err = c.pconn.ReadFrom(b)
			if err != nil {
				select {
				case c.udpRecvCh <- udpReadResult{err: err}:
				case <-c.donec:
				}
				return
			}
			if stun.Is(b[:n]) {
				c.stunReceiveFunc.Load().(func([]byte, *net.UDPAddr))(b, addr)
				continue
			}

			addr := pAddr.(*net.UDPAddr)
			addr.IP = addr.IP.To4()
			select {
			case c.udpRecvCh <- udpReadResult{n: n, addr: addr}:
			case <-c.donec:
			}
			return
		}
	}()

	select {
	case dm := <-c.derpRecvCh:
		// Cancel the pconn read goroutine
		c.pconn.SetReadDeadline(aLongTimeAgo)
		select {
		case <-c.udpRecvCh:
			// It's likely an error, since we just canceled the read.
			// But there's a small window where the pconn.ReadFrom could've
			// succeeded but not yet sent, and we got into the derp recv path
			// first. In that case this udpReadResult is a real non-err packet
			// and we need to choose which to use. Currently, arbitrarily, we currently
			// select DERP and discard this result entirely.
			// The main point of this receive, though, is to make sure that the goroutine
			// is done with our b []byte buf.
			c.pconn.SetReadDeadline(time.Time{})
		case <-c.donec:
			return 0, nil, nil, errors.New("Conn closed")
		}
		n, addr = dm.n, dm.derpAddr
		ncopy := dm.copyBuf(b)
		if ncopy != n {
			err = fmt.Errorf("received DERP packet of length %d that's too big for WireGuard ReceiveIPv4 buf size %d", n, ncopy)
			log.Printf("magicsock: %v", err)
			return 0, nil, nil, err
		}

	case um := <-c.udpRecvCh:
		if um.err != nil {
			return 0, nil, nil, err
		}
		n, addr = um.n, um.addr
	}

	addrSet, _ := c.findIndexedAddrSet(addr)
	if addrSet == nil {
		// The peer that sent this packet has roamed beyond the
		// knowledge provided by the control server.
		// If the packet is valid wireguard will call UpdateDst
		// on the original endpoint using this addr.
		return n, (*singleEndpoint)(addr), addr, nil
	}
	return n, addrSet, addr, nil
}

func (c *Conn) ReceiveIPv6(buff []byte) (int, device.Endpoint, *net.UDPAddr, error) {
	// TODO(crawshaw): IPv6 support
	return 0, nil, nil, syscall.EAFNOSUPPORT
}

func (c *Conn) SetPrivateKey(privateKey wgcfg.PrivateKey) error {
	c.privateKey = key.Private(privateKey)
	return nil
}

func (c *Conn) SetMark(value uint32) error { return nil }

func (c *Conn) Close() error {
	select {
	case <-c.donec:
		return nil
	default:
	}
	close(c.donec)
	c.epUpdateCancel()
	for _, dc := range c.derpConn {
		dc.Close()
	}
	return c.pconn.Close()
}

func (c *Conn) reSTUN() {
	select {
	case c.startEpUpdate <- struct{}{}:
	case <-c.epUpdateCtx.Done():
	}
}

func (c *Conn) LinkChange() {
	defer c.reSTUN()

	if c.pconnPort != 0 {
		c.pconn.mu.Lock()
		if err := c.pconn.pconn.Close(); err != nil {
			log.Printf("magicsock: link change close failed: %v", err)
		}
		packetConn, err := net.ListenPacket("udp4", fmt.Sprintf(":%d", c.pconnPort))
		if err == nil {
			log.Printf("magicsock: link change rebound port: %d", c.pconnPort)
			c.pconn.pconn = packetConn.(*net.UDPConn)
			c.pconn.mu.Unlock()
			return
		}
		log.Printf("magicsock: link change unable to bind fixed port %d: %v, falling back to random port", c.pconnPort, err)
		c.pconn.mu.Unlock()
	}

	log.Printf("magicsock: link change, binding new port")
	packetConn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		log.Printf("magicsock: link change failed to bind new port: %v", err)
		return
	}
	c.pconn.Reset(packetConn.(*net.UDPConn))
}

// AddrSet is a set of UDP addresses that implements wireguard/device.Endpoint.
type AddrSet struct {
	publicKey key.Public    // peer public key used for DERP communication
	addrs     []net.UDPAddr // ordered priority list provided by wgengine

	mu sync.Mutex // guards roamAddr and curAddr

	// roamAddr is non-nil if/when we receive a correctly signed
	// WireGuard packet from an unexpected address. If so, we
	// remember it and send responses there in the future, but
	// this should hopefully never be used (or at least used
	// rarely) in the case that all the components of Tailscale
	// are correctly learning/sharing the network map details.
	roamAddr *net.UDPAddr

	// curAddr is an index into addrs of the highest-priority
	// address a valid packet has been received from so far.
	// If no valid packet from addrs has been received, curAddr is -1.
	curAddr int
}

var noAddr = &net.UDPAddr{
	IP:   net.ParseIP("127.127.127.127"),
	Port: 127,
}

func (a *AddrSet) dst() *net.UDPAddr {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.roamAddr != nil {
		return a.roamAddr
	}
	if len(a.addrs) == 0 {
		return noAddr
	}
	i := a.curAddr
	if i == -1 {
		i = 0
	}
	return &a.addrs[i]
}

// packUDPAddr packs a UDPAddr in the form wanted by WireGuard.
func packUDPAddr(ua *net.UDPAddr) []byte {
	ip := ua.IP.To4()
	if ip == nil {
		ip = ua.IP
	}
	b := make([]byte, 0, len(ip)+2)
	b = append(b, ip...)
	b = append(b, byte(ua.Port))
	b = append(b, byte(ua.Port>>8))
	return b
}

func (a *AddrSet) DstToBytes() []byte {
	return packUDPAddr(a.dst())
}
func (a *AddrSet) DstToString() string {
	dst := a.dst()
	return dst.String()
}
func (a *AddrSet) DstIP() net.IP {
	return a.dst().IP
}
func (a *AddrSet) SrcIP() net.IP       { return nil }
func (a *AddrSet) SrcToString() string { return "" }
func (a *AddrSet) ClearSrc()           {}

func (a *AddrSet) UpdateDst(new *net.UDPAddr) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.roamAddr != nil {
		if equalUDPAddr(a.roamAddr, new) {
			// Packet from the current roaming address, no logging.
			// This is a hot path for established connections.
			return nil
		}
	} else if a.curAddr >= 0 && equalUDPAddr(new, &a.addrs[a.curAddr]) {
		// Packet from current-priority address, no logging.
		// This is a hot path for established connections.
		return nil
	}

	index := -1
	for i := range a.addrs {
		if equalUDPAddr(new, &a.addrs[i]) {
			index = i
			break
		}
	}

	publicKey := wgcfg.Key(a.publicKey)
	pk := publicKey.ShortString()
	old := "<none>"
	if a.curAddr >= 0 {
		old = a.addrs[a.curAddr].String()
	}

	switch {
	case index == -1:
		if a.roamAddr == nil {
			log.Printf("magicsock: rx %s from roaming address %s, set as new priority", pk, new)
		} else {
			log.Printf("magicsock: rx %s from roaming address %s, replaces roaming address %s", pk, new, a.roamAddr)
		}
		a.roamAddr = new

	case a.roamAddr != nil:
		log.Printf("magicsock: rx %s from known %s (%d), replaces roaming address %s", pk, new, index, a.roamAddr)
		a.roamAddr = nil
		a.curAddr = index

	case a.curAddr == -1:
		log.Printf("magicsock: rx %s from %s (%d/%d), set as new priority", pk, new, index, len(a.addrs))
		a.curAddr = index

	case index < a.curAddr:
		log.Printf("magicsock: rx %s from low-pri %s (%d), keeping current %s (%d)", pk, new, index, old, a.curAddr)

	default: // index > a.curAddr
		log.Printf("magicsock: rx %s from %s (%d/%d), replaces old priority %s", pk, new, index, len(a.addrs), old)
		a.curAddr = index
	}

	return nil
}

func equalUDPAddr(x, y *net.UDPAddr) bool {
	return x.Port == y.Port && x.IP.Equal(y.IP)
}

func (a *AddrSet) String() string {
	a.mu.Lock()
	defer a.mu.Unlock()

	buf := new(strings.Builder)
	buf.WriteByte('[')
	if a.roamAddr != nil {
		fmt.Fprintf(buf, "roam:%s:%d", a.roamAddr.IP, a.roamAddr.Port)
	}
	for i, addr := range a.addrs {
		if i > 0 || a.roamAddr != nil {
			buf.WriteString(", ")
		}
		fmt.Fprintf(buf, "%s:%d", addr.IP, addr.Port)
		if a.curAddr == i {
			buf.WriteByte('*')
		}
	}
	buf.WriteByte(']')

	return buf.String()
}

func (a *AddrSet) Addrs() []wgcfg.Endpoint {
	var eps []wgcfg.Endpoint
	for _, addr := range a.addrs {
		eps = append(eps, wgcfg.Endpoint{
			Host: addr.IP.String(),
			Port: uint16(addr.Port),
		})
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.roamAddr != nil {
		eps = append(eps, wgcfg.Endpoint{
			Host: a.roamAddr.IP.String(),
			Port: uint16(a.roamAddr.Port),
		})
	}
	return eps
}

// CreateEndpoint is called by WireGuard to connect to an endpoint.
// The key is the public key of the peer and addrs is a
// comma-separated list of UDP ip:ports.
func (c *Conn) CreateEndpoint(key [32]byte, addrs string) (device.Endpoint, error) {
	pk := wgcfg.Key(key)
	log.Printf("magicsock: CreateEndpoint: key=%s: %s", pk.ShortString(), addrs)
	a := &AddrSet{
		publicKey: key,
		curAddr:   -1,
	}

	if addrs != "" {
		for _, ep := range strings.Split(addrs, ",") {
			addr, err := net.ResolveUDPAddr("udp", ep)
			if err != nil {
				return nil, err
			}
			if ip4 := addr.IP.To4(); ip4 != nil {
				addr.IP = ip4
			}
			a.addrs = append(a.addrs, *addr)
		}
	}

	c.indexedAddrsMu.Lock()
	for i, addr := range a.addrs {
		var epAddr udpAddr
		copy(epAddr.ip.Addr[:], addr.IP.To16())
		epAddr.port = uint16(addr.Port)
		c.indexedAddrs[epAddr] = indexedAddrSet{
			addr:  a,
			index: i,
		}
	}
	c.indexedAddrsMu.Unlock()

	return a, nil
}

type singleEndpoint net.UDPAddr

func (e *singleEndpoint) ClearSrc()           {}
func (e *singleEndpoint) DstIP() net.IP       { return (*net.UDPAddr)(e).IP }
func (e *singleEndpoint) SrcIP() net.IP       { return nil }
func (e *singleEndpoint) SrcToString() string { return "" }
func (e *singleEndpoint) DstToString() string { return (*net.UDPAddr)(e).String() }
func (e *singleEndpoint) DstToBytes() []byte  { return packUDPAddr((*net.UDPAddr)(e)) }
func (e *singleEndpoint) UpdateDst(dst *net.UDPAddr) error {
	return fmt.Errorf("magicsock.singleEndpoint(%s).UpdateDst(%s): should never be called", (*net.UDPAddr)(e), dst)
}
func (e *singleEndpoint) Addrs() []wgcfg.Endpoint {
	return []wgcfg.Endpoint{{
		Host: e.IP.String(),
		Port: uint16(e.Port),
	}}
}

// RebindingUDPConn is a UDP socket that can be re-bound.
// Unix has no notion of re-binding a socket, so we swap it out for a new one.
type RebindingUDPConn struct {
	mu    sync.Mutex
	pconn *net.UDPConn
}

func (c *RebindingUDPConn) Reset(pconn *net.UDPConn) {
	c.mu.Lock()
	old := c.pconn
	c.pconn = pconn
	c.mu.Unlock()

	if old != nil {
		old.Close()
	}
}

func (c *RebindingUDPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		c.mu.Lock()
		pconn := c.pconn
		c.mu.Unlock()

		n, addr, err := pconn.ReadFrom(b)
		if err != nil {
			c.mu.Lock()
			pconn2 := c.pconn
			c.mu.Unlock()

			if pconn != pconn2 {
				continue
			}
		}
		return n, addr, err
	}
}

func (c *RebindingUDPConn) LocalAddr() *net.UDPAddr {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pconn.LocalAddr().(*net.UDPAddr)
}

func (c *RebindingUDPConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pconn.Close()
}

func (c *RebindingUDPConn) SetReadDeadline(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pconn.SetReadDeadline(t)
}

func (c *RebindingUDPConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	for {
		c.mu.Lock()
		pconn := c.pconn
		c.mu.Unlock()

		n, err := pconn.WriteToUDP(b, addr)
		if err != nil {
			c.mu.Lock()
			pconn2 := c.pconn
			c.mu.Unlock()

			if pconn != pconn2 {
				continue
			}
		}
		return n, err
	}
}

func (c *RebindingUDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	for {
		c.mu.Lock()
		pconn := c.pconn
		c.mu.Unlock()

		n, err := pconn.WriteTo(b, addr)
		if err != nil {
			c.mu.Lock()
			pconn2 := c.pconn
			c.mu.Unlock()

			if pconn != pconn2 {
				continue
			}
		}
		return n, err
	}
}
