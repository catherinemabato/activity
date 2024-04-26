// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package health is a registry for other packages to report & check
// overall health status of the node.
package health

import (
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
	"tailscale.com/types/opt"
	"tailscale.com/util/mak"
	"tailscale.com/util/multierr"
	"tailscale.com/util/set"
)

var (
	mu           sync.Mutex
	debugHandler map[string]http.Handler
)

// Global is a global health tracker for the process.
//
// TODO(bradfitz): finish moving all reference to this plumb it (ultimately out
// from tsd.System) so a process can have multiple tsnet/etc instances with
// their own health trackers. But for now (2024-04-25), the tsd.System value
// given out is just this one, until that's the only remaining Global reference
// remaining.
var Global = new(Tracker)

type Tracker struct {
	// mu guards everything in this var block.
	mu sync.Mutex

	warnables   []*Warnable // keys ever set
	warnableVal map[*Warnable]error

	sysErr   map[Subsystem]error                   // subsystem => err (or nil for no error)
	watchers set.HandleSet[func(Subsystem, error)] // opt func to run if error state changes
	timer    *time.Timer

	inMapPoll               bool
	inMapPollSince          time.Time
	lastMapPollEndedAt      time.Time
	lastStreamedMapResponse time.Time
	derpHomeRegion          int
	derpHomeless            bool
	derpRegionConnected     map[int]bool
	derpRegionHealthProblem map[int]string
	derpRegionLastFrame     map[int]time.Time
	lastMapRequestHeard     time.Time // time we got a 200 from control for a MapRequest
	ipnState                string
	ipnWantRunning          bool
	anyInterfaceUp          opt.Bool // empty means unknown (assume true)
	udp4Unbound             bool
	controlHealth           []string
	lastLoginErr            error
	localLogConfigErr       error
	tlsConnectionErrors     map[string]error // map[ServerName]error
}

// Subsystem is the name of a subsystem whose health can be monitored.
type Subsystem string

const (
	// SysOverall is the name representing the overall health of
	// the system, rather than one particular subsystem.
	SysOverall = Subsystem("overall")

	// SysRouter is the name of the wgengine/router subsystem.
	SysRouter = Subsystem("router")

	// SysDNS is the name of the net/dns subsystem.
	SysDNS = Subsystem("dns")

	// SysDNSOS is the name of the net/dns OSConfigurator subsystem.
	SysDNSOS = Subsystem("dns-os")

	// SysDNSManager is the name of the net/dns manager subsystem.
	SysDNSManager = Subsystem("dns-manager")

	// SysTKA is the name of the tailnet key authority subsystem.
	SysTKA = Subsystem("tailnet-lock")
)

// NewWarnable returns a new warnable item that the caller can mark as health or
// in warning state via Tracker.SetWarnable.
//
// NewWarnable is generally called in init and stored in a package global. It
// can be used by multiple Trackers.
func NewWarnable(opts ...WarnableOpt) *Warnable {
	w := new(Warnable)
	for _, o := range opts {
		o.mod(w)
	}
	return w
}

// WarnableOpt is an option passed to NewWarnable.
type WarnableOpt interface {
	mod(*Warnable)
}

// WithMapDebugFlag returns a WarnableOpt for NewWarnable that makes the returned
// Warnable report itself to the coordination server as broken with this
// string in MapRequest.DebugFlag when Set to a non-nil value.
func WithMapDebugFlag(name string) WarnableOpt {
	return warnOptFunc(func(w *Warnable) {
		w.debugFlag = name
	})
}

// WithConnectivityImpact returns an option which makes a Warnable annotated as
// something that could be breaking external network connectivity on the
// machine. This will make the warnable returned by OverallError alongside
// network connectivity errors.
func WithConnectivityImpact() WarnableOpt {
	return warnOptFunc(func(w *Warnable) {
		w.hasConnectivityImpact = true
	})
}

type warnOptFunc func(*Warnable)

func (f warnOptFunc) mod(w *Warnable) { f(w) }

// Warnable is a health check item that may or may not be in a bad warning state.
// The caller of NewWarnable is responsible for calling Tracker.SetWarnable to update the state.
type Warnable struct {
	debugFlag string // optional MapRequest.DebugFlag to send when unhealthy

	// If true, this warning is related to configuration of networking stack
	// on the machine that impacts connectivity.
	hasConnectivityImpact bool
}

// nil reports whether t is nil.
// It exists to accept nil *Tracker receivers on all methods
// to at least not crash. But because a nil receiver indicates
// some lost Tracker plumbing, we want to capture stack trace
// samples when it occurs.
func (t *Tracker) nil() bool {
	if t != nil {
		return false
	}
	// TODO(bradfitz): open source our "unexpected" package
	// and use it here to capture samples of stacks where
	// t is nil.
	return true
}

// Set updates the Warnable's state.
// If non-nil, it's considered unhealthy.
func (t *Tracker) SetWarnable(w *Warnable, err error) {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	l0 := len(t.warnableVal)
	mak.Set(&t.warnableVal, w, err)
	if len(t.warnableVal) != l0 {
		t.warnables = append(t.warnables, w)
	}
}

// AppendWarnableDebugFlags appends to base any health items that are currently in failed
// state and were created with MapDebugFlag.
func (t *Tracker) AppendWarnableDebugFlags(base []string) []string {
	if t.nil() {
		return base
	}

	ret := base

	t.mu.Lock()
	defer t.mu.Unlock()
	for w, err := range t.warnableVal {
		if w.debugFlag == "" {
			continue
		}
		if err != nil {
			ret = append(ret, w.debugFlag)
		}
	}
	sort.Strings(ret[len(base):]) // sort the new ones
	return ret
}

// RegisterWatcher adds a function that will be called if an
// error changes state either to unhealthy or from unhealthy. It is
// not called on transition from unknown to healthy. It must be non-nil
// and is run in its own goroutine. The returned func unregisters it.
func (t *Tracker) RegisterWatcher(cb func(key Subsystem, err error)) (unregister func()) {
	if t.nil() {
		return func() {}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.watchers == nil {
		t.watchers = set.HandleSet[func(Subsystem, error)]{}
	}
	handle := t.watchers.Add(cb)
	if t.timer == nil {
		t.timer = time.AfterFunc(time.Minute, t.timerSelfCheck)
	}
	return func() {
		t.mu.Lock()
		defer t.mu.Unlock()
		delete(t.watchers, handle)
		if len(t.watchers) == 0 && t.timer != nil {
			t.timer.Stop()
			t.timer = nil
		}
	}
}

// SetRouterHealth sets the state of the wgengine/router.Router.
func (t *Tracker) SetRouterHealth(err error) { t.setErr(SysRouter, err) }

// RouterHealth returns the wgengine/router.Router error state.
func (t *Tracker) RouterHealth() error { return t.get(SysRouter) }

// SetDNSHealth sets the state of the net/dns.Manager
func (t *Tracker) SetDNSHealth(err error) { t.setErr(SysDNS, err) }

// DNSHealth returns the net/dns.Manager error state.
func (t *Tracker) DNSHealth() error { return t.get(SysDNS) }

// SetDNSOSHealth sets the state of the net/dns.OSConfigurator
func (t *Tracker) SetDNSOSHealth(err error) { t.setErr(SysDNSOS, err) }

// SetDNSManagerHealth sets the state of the Linux net/dns manager's
// discovery of the /etc/resolv.conf situation.
func (t *Tracker) SetDNSManagerHealth(err error) { t.setErr(SysDNSManager, err) }

// DNSOSHealth returns the net/dns.OSConfigurator error state.
func (t *Tracker) DNSOSHealth() error { return t.get(SysDNSOS) }

// SetTKAHealth sets the health of the tailnet key authority.
func (t *Tracker) SetTKAHealth(err error) { t.setErr(SysTKA, err) }

// TKAHealth returns the tailnet key authority error state.
func (t *Tracker) TKAHealth() error { return t.get(SysTKA) }

// SetLocalLogConfigHealth sets the error state of this client's local log configuration.
func (t *Tracker) SetLocalLogConfigHealth(err error) {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.localLogConfigErr = err
}

// SetTLSConnectionError sets the error state for connections to a specific
// host. Setting the error to nil will clear any previously-set error.
func (t *Tracker) SetTLSConnectionError(host string, err error) {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err == nil {
		delete(t.tlsConnectionErrors, host)
	} else {
		mak.Set(&t.tlsConnectionErrors, host, err)
	}
}

func RegisterDebugHandler(typ string, h http.Handler) {
	mu.Lock()
	defer mu.Unlock()
	mak.Set(&debugHandler, typ, h)
}

func DebugHandler(typ string) http.Handler {
	mu.Lock()
	defer mu.Unlock()
	return debugHandler[typ]
}

func (t *Tracker) get(key Subsystem) error {
	if t.nil() {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.sysErr[key]
}

func (t *Tracker) setErr(key Subsystem, err error) {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.setLocked(key, err)
}

func (t *Tracker) setLocked(key Subsystem, err error) {
	if t.sysErr == nil {
		t.sysErr = map[Subsystem]error{}
	}
	old, ok := t.sysErr[key]
	if !ok && err == nil {
		// Initial happy path.
		t.sysErr[key] = nil
		t.selfCheckLocked()
		return
	}
	if ok && (old == nil) == (err == nil) {
		// No change in overall error status (nil-vs-not), so
		// don't run callbacks, but exact error might've
		// changed, so note it.
		if err != nil {
			t.sysErr[key] = err
		}
		return
	}
	t.sysErr[key] = err
	t.selfCheckLocked()
	for _, cb := range t.watchers {
		go cb(key, err)
	}
}

func (t *Tracker) SetControlHealth(problems []string) {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.controlHealth = problems
	t.selfCheckLocked()
}

// GotStreamedMapResponse notes that we got a tailcfg.MapResponse
// message in streaming mode, even if it's just a keep-alive message.
//
// This also notes that a map poll is in progress. To unset that, call
// SetOutOfPollNetMap().
func (t *Tracker) GotStreamedMapResponse() {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastStreamedMapResponse = time.Now()
	if !t.inMapPoll {
		t.inMapPoll = true
		t.inMapPollSince = time.Now()
	}
	t.selfCheckLocked()
}

// SetOutOfPollNetMap records that the client is no longer in
// an HTTP map request long poll to the control plane.
func (t *Tracker) SetOutOfPollNetMap() {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.inMapPoll {
		return
	}
	t.inMapPoll = false
	t.lastMapPollEndedAt = time.Now()
	t.selfCheckLocked()
}

// GetInPollNetMap reports whether the client has an open
// HTTP long poll open to the control plane.
func (t *Tracker) GetInPollNetMap() bool {
	if t.nil() {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.inMapPoll
}

// SetMagicSockDERPHome notes what magicsock's view of its home DERP is.
//
// The homeless parameter is whether magicsock is running in DERP-disconnected
// mode, without discovering and maintaining a connection to its home DERP.
func (t *Tracker) SetMagicSockDERPHome(region int, homeless bool) {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.derpHomeRegion = region
	t.derpHomeless = homeless
	t.selfCheckLocked()
}

// NoteMapRequestHeard notes whenever we successfully sent a map request
// to control for which we received a 200 response.
func (t *Tracker) NoteMapRequestHeard(mr *tailcfg.MapRequest) {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	// TODO: extract mr.HostInfo.NetInfo.PreferredDERP, compare
	// against SetMagicSockDERPHome and
	// SetDERPRegionConnectedState

	t.lastMapRequestHeard = time.Now()
	t.selfCheckLocked()
}

func (t *Tracker) SetDERPRegionConnectedState(region int, connected bool) {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	mak.Set(&t.derpRegionConnected, region, connected)
	t.selfCheckLocked()
}

// SetDERPRegionHealth sets or clears any problem associated with the
// provided DERP region.
func (t *Tracker) SetDERPRegionHealth(region int, problem string) {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if problem == "" {
		delete(t.derpRegionHealthProblem, region)
	} else {
		mak.Set(&t.derpRegionHealthProblem, region, problem)
	}
	t.selfCheckLocked()
}

// NoteDERPRegionReceivedFrame is called to note that a frame was received from
// the given DERP region at the current time.
func (t *Tracker) NoteDERPRegionReceivedFrame(region int) {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	mak.Set(&t.derpRegionLastFrame, region, time.Now())
	t.selfCheckLocked()
}

// GetDERPRegionReceivedTime returns the last time that a frame was received
// from the given DERP region, or the zero time if no communication with that
// region has occurred.
func (t *Tracker) GetDERPRegionReceivedTime(region int) time.Time {
	if t.nil() {
		return time.Time{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.derpRegionLastFrame[region]
}

// state is an ipn.State.String() value: "Running", "Stopped", "NeedsLogin", etc.
func (t *Tracker) SetIPNState(state string, wantRunning bool) {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ipnState = state
	t.ipnWantRunning = wantRunning
	t.selfCheckLocked()
}

// SetAnyInterfaceUp sets whether any network interface is up.
func (t *Tracker) SetAnyInterfaceUp(up bool) {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.anyInterfaceUp.Set(up)
	t.selfCheckLocked()
}

// SetUDP4Unbound sets whether the udp4 bind failed completely.
func (t *Tracker) SetUDP4Unbound(unbound bool) {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.udp4Unbound = unbound
	t.selfCheckLocked()
}

// SetAuthRoutineInError records the latest error encountered as a result of a
// login attempt. Providing a nil error indicates successful login, or that
// being logged in w/coordination is not currently desired.
func (t *Tracker) SetAuthRoutineInError(err error) {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastLoginErr = err
}

func (t *Tracker) timerSelfCheck() {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	checkReceiveFuncs()
	t.selfCheckLocked()
	if t.timer != nil {
		t.timer.Reset(time.Minute)
	}
}

func (t *Tracker) selfCheckLocked() {
	if t.ipnState == "" {
		// Don't check yet.
		return
	}
	t.setLocked(SysOverall, t.overallErrorLocked())
}

// OverallError returns a summary of the health state.
//
// If there are multiple problems, the error will be of type
// multierr.Error.
func (t *Tracker) OverallError() error {
	if t.nil() {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.overallErrorLocked()
}

var fakeErrForTesting = envknob.RegisterString("TS_DEBUG_FAKE_HEALTH_ERROR")

// networkErrorfLocked creates an error that indicates issues with outgoing network
// connectivity. Any active warnings related to network connectivity will
// automatically be appended to it.
//
// t.mu must be held.
func (t *Tracker) networkErrorfLocked(format string, a ...any) error {
	errs := []error{
		fmt.Errorf(format, a...),
	}
	for _, w := range t.warnables {
		if !w.hasConnectivityImpact {
			continue
		}
		if err := t.warnableVal[w]; err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == 1 {
		return errs[0]
	}
	return multierr.New(errs...)
}

var errNetworkDown = errors.New("network down")
var errNotInMapPoll = errors.New("not in map poll")
var errNoDERPHome = errors.New("no DERP home")
var errNoUDP4Bind = errors.New("no udp4 bind")

func (t *Tracker) overallErrorLocked() error {
	if v, ok := t.anyInterfaceUp.Get(); ok && !v {
		return errNetworkDown
	}
	if t.localLogConfigErr != nil {
		return t.localLogConfigErr
	}
	if !t.ipnWantRunning {
		return fmt.Errorf("state=%v, wantRunning=%v", t.ipnState, t.ipnWantRunning)
	}
	if t.lastLoginErr != nil {
		return fmt.Errorf("not logged in, last login error=%v", t.lastLoginErr)
	}
	now := time.Now()
	if !t.inMapPoll && (t.lastMapPollEndedAt.IsZero() || now.Sub(t.lastMapPollEndedAt) > 10*time.Second) {
		return errNotInMapPoll
	}
	const tooIdle = 2*time.Minute + 5*time.Second
	if d := now.Sub(t.lastStreamedMapResponse).Round(time.Second); d > tooIdle {
		return t.networkErrorfLocked("no map response in %v", d)
	}
	if !t.derpHomeless {
		rid := t.derpHomeRegion
		if rid == 0 {
			return errNoDERPHome
		}
		if !t.derpRegionConnected[rid] {
			return t.networkErrorfLocked("not connected to home DERP region %v", rid)
		}
		if d := now.Sub(t.derpRegionLastFrame[rid]).Round(time.Second); d > tooIdle {
			return t.networkErrorfLocked("haven't heard from home DERP region %v in %v", rid, d)
		}
	}
	if t.udp4Unbound {
		return errNoUDP4Bind
	}

	// TODO: use
	_ = t.inMapPollSince
	_ = t.lastMapPollEndedAt
	_ = t.lastStreamedMapResponse
	_ = t.lastMapRequestHeard

	var errs []error
	for _, recv := range receiveFuncs {
		if recv.missing {
			errs = append(errs, fmt.Errorf("%s is not running", recv.name))
		}
	}
	for sys, err := range t.sysErr {
		if err == nil || sys == SysOverall {
			continue
		}
		errs = append(errs, fmt.Errorf("%v: %w", sys, err))
	}
	for _, w := range t.warnables {
		if err := t.warnableVal[w]; err != nil {
			errs = append(errs, err)
		}
	}
	for regionID, problem := range t.derpRegionHealthProblem {
		errs = append(errs, fmt.Errorf("derp%d: %v", regionID, problem))
	}
	for _, s := range t.controlHealth {
		errs = append(errs, errors.New(s))
	}
	if err := envknob.ApplyDiskConfigError(); err != nil {
		errs = append(errs, err)
	}
	for serverName, err := range t.tlsConnectionErrors {
		errs = append(errs, fmt.Errorf("TLS connection error for %q: %w", serverName, err))
	}
	if e := fakeErrForTesting(); len(errs) == 0 && e != "" {
		return errors.New(e)
	}
	sort.Slice(errs, func(i, j int) bool {
		// Not super efficient (stringifying these in a sort), but probably max 2 or 3 items.
		return errs[i].Error() < errs[j].Error()
	})
	return multierr.New(errs...)
}

var (
	ReceiveIPv4 = ReceiveFuncStats{name: "ReceiveIPv4"}
	ReceiveIPv6 = ReceiveFuncStats{name: "ReceiveIPv6"}
	ReceiveDERP = ReceiveFuncStats{name: "ReceiveDERP"}

	receiveFuncs = []*ReceiveFuncStats{&ReceiveIPv4, &ReceiveIPv6, &ReceiveDERP}
)

func init() {
	if runtime.GOOS == "js" {
		receiveFuncs = receiveFuncs[2:] // ignore IPv4 and IPv6
	}
}

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
