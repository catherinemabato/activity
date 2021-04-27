// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package health is a registry for other packages to report & check
// overall health status of the node.
package health

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-multierror/multierror"
	"tailscale.com/tailcfg"
)

var (
	// mu guards everything in this var block.
	mu sync.Mutex

	sysErr   = map[Subsystem]error{}                     // error key => err (or nil for no error)
	watchers = map[*watchHandle]func(Subsystem, error){} // opt func to run if error state changes
	timer    *time.Timer

	inMapPoll               bool
	inMapPollSince          time.Time
	lastMapPollEndedAt      time.Time
	lastStreamedMapResponse time.Time
	derpHomeRegion          int
	derpRegionConnected     = map[int]bool{}
	derpRegionLastFrame     = map[int]time.Time{}
	lastMapRequestHeard     time.Time // time we got a 200 from control for a MapRequest
	ipnState                string
	ipnWantRunning          bool
	anyInterfaceUp          = true // until told otherwise
)

// Subsystem is the name of a subsystem whose health can be monitored.
type Subsystem string

const (
	// SysOverall is the name representing the overall health of
	// the system, rather than one particular subsystem.
	SysOverall = Subsystem("overall")

	// SysRouter is the name the wgengine/router subsystem.
	SysRouter = Subsystem("router")

	// SysDNS is the name of the net/dns subsystem.
	SysDNS = Subsystem("dns")

	// SysNetworkCategory is the name of the subsystem that sets
	// the Windows network adapter's "category" (public, private, domain).
	// If it's unhealthy, the Windows firewall rules won't match.
	SysNetworkCategory = Subsystem("network-category")
)

type watchHandle byte

// RegisterWatcher adds a function that will be called if an
// error changes state either to unhealthy or from unhealthy. It is
// not called on transition from unknown to healthy. It must be non-nil
// and is run in its own goroutine. The returned func unregisters it.
func RegisterWatcher(cb func(key Subsystem, err error)) (unregister func()) {
	mu.Lock()
	defer mu.Unlock()
	handle := new(watchHandle)
	watchers[handle] = cb
	if timer == nil {
		timer = time.AfterFunc(time.Minute, timerSelfCheck)
	}
	return func() {
		mu.Lock()
		defer mu.Unlock()
		delete(watchers, handle)
		if len(watchers) == 0 && timer != nil {
			timer.Stop()
			timer = nil
		}
	}
}

// SetRouterHealth sets the state of the wgengine/router.Router.
func SetRouterHealth(err error) { set(SysRouter, err) }

// RouterHealth returns the wgengine/router.Router error state.
func RouterHealth() error { return get(SysRouter) }

// SetDNSHealth sets the state of the net/dns.Manager
func SetDNSHealth(err error) { set(SysDNS, err) }

// DNSHealth returns the net/dns.Manager error state.
func DNSHealth() error { return get(SysDNS) }

// SetNetworkCategoryHealth sets the state of setting the network adaptor's category.
// This only applies on Windows.
func SetNetworkCategoryHealth(err error) { set(SysNetworkCategory, err) }

func NetworkCategoryHealth() error { return get(SysNetworkCategory) }

func get(key Subsystem) error {
	mu.Lock()
	defer mu.Unlock()
	return sysErr[key]
}

func set(key Subsystem, err error) {
	mu.Lock()
	defer mu.Unlock()
	setLocked(key, err)
}

func setLocked(key Subsystem, err error) {
	old, ok := sysErr[key]
	if !ok && err == nil {
		// Initial happy path.
		sysErr[key] = nil
		selfCheckLocked()
		return
	}
	if ok && (old == nil) == (err == nil) {
		// No change in overall error status (nil-vs-not), so
		// don't run callbacks, but exact error might've
		// changed, so note it.
		if err != nil {
			sysErr[key] = err
		}
		return
	}
	sysErr[key] = err
	selfCheckLocked()
	for _, cb := range watchers {
		go cb(key, err)
	}
}

// GotStreamedMapResponse notes that we got a tailcfg.MapResponse
// message in streaming mode, even if it's just a keep-alive message.
func GotStreamedMapResponse() {
	mu.Lock()
	defer mu.Unlock()
	lastStreamedMapResponse = time.Now()
	selfCheckLocked()
}

// SetInPollNetMap records that we're in
func SetInPollNetMap(v bool) {
	mu.Lock()
	defer mu.Unlock()
	if v == inMapPoll {
		return
	}
	inMapPoll = v
	if v {
		inMapPollSince = time.Now()
	} else {
		lastMapPollEndedAt = time.Now()
	}
}

// SetMagicSockDERPHome notes what magicsock's view of its home DERP is.
func SetMagicSockDERPHome(region int) {
	mu.Lock()
	defer mu.Unlock()
	derpHomeRegion = region
	selfCheckLocked()
}

// NoteMapRequestHeard notes whenever we successfully sent a map request
// to control for which we received a 200 response.
func NoteMapRequestHeard(mr *tailcfg.MapRequest) {
	mu.Lock()
	defer mu.Unlock()
	// TODO: extract mr.HostInfo.NetInfo.PreferredDERP, compare
	// against SetMagicSockDERPHome and
	// SetDERPRegionConnectedState

	lastMapRequestHeard = time.Now()
	selfCheckLocked()
}

func SetDERPRegionConnectedState(region int, connected bool) {
	mu.Lock()
	defer mu.Unlock()
	derpRegionConnected[region] = connected
	selfCheckLocked()
}

func NoteDERPRegionReceivedFrame(region int) {
	mu.Lock()
	defer mu.Unlock()
	derpRegionLastFrame[region] = time.Now()
	selfCheckLocked()
}

// state is an ipn.State.String() value: "Running", "Stopped", "NeedsLogin", etc.
func SetIPNState(state string, wantRunning bool) {
	mu.Lock()
	defer mu.Unlock()
	ipnState = state
	ipnWantRunning = wantRunning
	selfCheckLocked()
}

// SetAnyInterfaceUp sets whether any network interface is up.
func SetAnyInterfaceUp(up bool) {
	mu.Lock()
	defer mu.Unlock()
	anyInterfaceUp = up
	selfCheckLocked()
}

func timerSelfCheck() {
	mu.Lock()
	defer mu.Unlock()
	checkReceiveFuncs()
	selfCheckLocked()
	if timer != nil {
		timer.Reset(time.Minute)
	}
}

func selfCheckLocked() {
	if ipnState == "" {
		// Don't check yet.
		return
	}
	setLocked(SysOverall, overallErrorLocked())
}

func overallErrorLocked() error {
	if !anyInterfaceUp {
		return errors.New("network down")
	}
	if ipnState != "Running" || !ipnWantRunning {
		return fmt.Errorf("state=%v, wantRunning=%v", ipnState, ipnWantRunning)
	}
	now := time.Now()
	if !inMapPoll && (lastMapPollEndedAt.IsZero() || now.Sub(lastMapPollEndedAt) > 10*time.Second) {
		return errors.New("not in map poll")
	}
	const tooIdle = 2*time.Minute + 5*time.Second
	if d := now.Sub(lastStreamedMapResponse).Round(time.Second); d > tooIdle {
		return fmt.Errorf("no map response in %v", d)
	}
	rid := derpHomeRegion
	if rid == 0 {
		return errors.New("no DERP home")
	}
	if !derpRegionConnected[rid] {
		return fmt.Errorf("not connected to home DERP region %v", rid)
	}
	if d := now.Sub(derpRegionLastFrame[rid]).Round(time.Second); d > tooIdle {
		return fmt.Errorf("haven't heard from home DERP region %v in %v", rid, d)
	}

	// TODO: use
	_ = inMapPollSince
	_ = lastMapPollEndedAt
	_ = lastStreamedMapResponse
	_ = lastMapRequestHeard

	var errs []error
	for _, recv := range receiveFuncs {
		if recv.missing {
			errs = append(errs, fmt.Errorf("%s is not running", recv.name))
		}
	}
	for sys, err := range sysErr {
		if err == nil || sys == SysOverall {
			continue
		}
		errs = append(errs, fmt.Errorf("%v: %w", sys, err))
	}
	sort.Slice(errs, func(i, j int) bool {
		// Not super efficient (stringifying these in a sort), but probably max 2 or 3 items.
		return errs[i].Error() < errs[j].Error()
	})
	return multierror.New(errs)
}

var (
	ReceiveIPv4 = ReceiveFuncStats{name: "ReceiveIPv4"}
	// ReceiveIPv6 isn't guaranteed to be running, so skip it for now.
	ReceiveDERP = ReceiveFuncStats{name: "ReceiveDERP"}

	receiveFuncs = []*ReceiveFuncStats{&ReceiveIPv4, &ReceiveDERP}
)

// ReceiveFuncStats tracks the calls made to a wireguard-go receive func.
type ReceiveFuncStats struct {
	// name is the name of the receive func.
	name string
	// numCalls is the number of times the receive func has ever been called.
	// It is required because it is possible for a receive func's wireguard-go goroutine
	// to be active even though the receive func isn't.
	// The wireguard-go goroutine alternates between calling the receive func and
	// processing what the func returned.
	numCalls uint64 // accessed atomically
	// prevNumCalls is the value of numCalls last time the health check examined it.
	prevNumCalls uint64
	// inCall indicates whether the receive func is currently running.
	inCall uint32 // bool, accessed atomically
	// missing indicates whether the receive func is not running.
	missing bool
}

func (s *ReceiveFuncStats) Enter() {
	atomic.AddUint64(&s.numCalls, 1)
	atomic.StoreUint32(&s.inCall, 1)
}

func (s *ReceiveFuncStats) Exit() {
	atomic.StoreUint32(&s.inCall, 0)
}

func checkReceiveFuncs() {
	for _, recv := range receiveFuncs {
		recv.missing = false
		prev := recv.prevNumCalls
		numCalls := atomic.LoadUint64(&recv.numCalls)
		recv.prevNumCalls = numCalls
		if numCalls > prev {
			// OK: the function has gotten called since last we checked
			continue
		}
		if atomic.LoadUint32(&recv.inCall) == 1 {
			// OK: the function is active, probably blocked due to inactivity
			continue
		}
		// Not OK: The function is not active, and not accumulating new calls.
		// It is probably MIA.
		recv.missing = true
	}
}
