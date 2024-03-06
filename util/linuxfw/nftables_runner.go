// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package linuxfw

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/logger"
	"tailscale.com/types/ptr"
)

const (
	chainNameForward     = "ts-forward"
	chainNameInput       = "ts-input"
	chainNamePostrouting = "ts-postrouting"
)

// chainTypeRegular is an nftables chain that does not apply to a hook.
const chainTypeRegular = ""

type chainInfo struct {
	table         *nftables.Table
	name          string
	chainType     nftables.ChainType
	chainHook     *nftables.ChainHook
	chainPriority *nftables.ChainPriority
	chainPolicy   *nftables.ChainPolicy
}

type nftable struct {
	Proto  nftables.TableFamily
	Filter *nftables.Table
	Nat    *nftables.Table
}

// nftablesRunner implements a netfilterRunner using the netlink based nftables
// library. As nftables allows for arbitrary tables and chains, there is a need
// to follow conventions in order to integrate well with a surrounding
// ecosystem. The rules installed by nftablesRunner have the following
// properties:
//   - Install rules that intend to take precedence over rules installed by
//     other software. Tailscale provides packet filtering for tailnet traffic
//     inside the daemon based on the tailnet ACL rules.
//   - As nftables "accept" is not final, rules from high priority tables (low
//     numbers) will fall through to lower priority tables (high numbers). In
//     order to effectively be 'final', we install "jump" rules into conventional
//     tables and chains that will reach an accept verdict inside those tables.
//   - The table and chain conventions followed here are those used by
//     `iptables-nft` and `ufw`, so that those tools co-exist and do not
//     negatively affect Tailscale function.
type nftablesRunner struct {
	conn *nftables.Conn
	nft4 *nftable
	nft6 *nftable

	v6Available    bool
	v6NATAvailable bool
}

func (n *nftablesRunner) ensurePreroutingChain(dst netip.Addr) (*nftables.Table, *nftables.Chain, error) {
	polAccept := nftables.ChainPolicyAccept
	table := n.getNFTByAddr(dst)
	nat, err := createTableIfNotExist(n.conn, table.Proto, "nat")
	if err != nil {
		return nil, nil, fmt.Errorf("error ensuring nat table: %w", err)
	}

	// ensure prerouting chain exists
	preroutingCh, err := getOrCreateChain(n.conn, chainInfo{
		table:         nat,
		name:          "PREROUTING",
		chainType:     nftables.ChainTypeNAT,
		chainHook:     nftables.ChainHookPrerouting,
		chainPriority: nftables.ChainPriorityNATDest,
		chainPolicy:   &polAccept,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("error ensuring prerouting chain: %w", err)
	}
	return nat, preroutingCh, nil
}

func (n *nftablesRunner) AddDNATRule(origDst netip.Addr, dst netip.Addr) error {
	nat, preroutingCh, err := n.ensurePreroutingChain(dst)
	if err != nil {
		return err
	}
	var daddrOffset, fam, dadderLen uint32
	if origDst.Is4() {
		daddrOffset = 16
		dadderLen = 4
		fam = unix.NFPROTO_IPV4
	} else {
		daddrOffset = 24
		dadderLen = 16
		fam = unix.NFPROTO_IPV6
	}

	dnatRule := &nftables.Rule{
		Table: nat,
		Chain: preroutingCh,
		Exprs: []expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       daddrOffset,
				Len:          dadderLen,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     origDst.AsSlice(),
			},
			&expr.Immediate{
				Register: 1,
				Data:     dst.AsSlice(),
			},
			&expr.NAT{
				Type:       expr.NATTypeDestNAT,
				Family:     fam,
				RegAddrMin: 1,
			},
		},
	}
	n.conn.InsertRule(dnatRule)
	return n.conn.Flush()
}

func (n *nftablesRunner) DNATNonTailscaleTraffic(tunname string, dst netip.Addr) error {
	nat, preroutingCh, err := n.ensurePreroutingChain(dst)
	if err != nil {
		return err
	}
	var famConst uint32
	if dst.Is4() {
		famConst = unix.NFPROTO_IPV4
	} else {
		famConst = unix.NFPROTO_IPV6
	}

	dnatRule := &nftables.Rule{
		Table: nat,
		Chain: preroutingCh,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     []byte(tunname),
			},
			&expr.Immediate{
				Register: 1,
				Data:     dst.AsSlice(),
			},
			&expr.NAT{
				Type:       expr.NATTypeDestNAT,
				Family:     famConst,
				RegAddrMin: 1,
			},
		},
	}
	n.conn.InsertRule(dnatRule)
	return n.conn.Flush()
}

func (n *nftablesRunner) AddSNATRuleForDst(src, dst netip.Addr) error {
	polAccept := nftables.ChainPolicyAccept
	table := n.getNFTByAddr(dst)
	nat, err := createTableIfNotExist(n.conn, table.Proto, "nat")
	if err != nil {
		return fmt.Errorf("error ensuring nat table exists: %w", err)
	}

	// ensure postrouting chain exists
	postRoutingCh, err := getOrCreateChain(n.conn, chainInfo{
		table:         nat,
		name:          "POSTROUTING",
		chainType:     nftables.ChainTypeNAT,
		chainHook:     nftables.ChainHookPostrouting,
		chainPriority: nftables.ChainPriorityNATSource,
		chainPolicy:   &polAccept,
	})
	if err != nil {
		return fmt.Errorf("error ensuring postrouting chain: %w", err)
	}
	var daddrOffset, fam, daddrLen uint32
	if dst.Is4() {
		daddrOffset = 16
		daddrLen = 4
		fam = unix.NFPROTO_IPV4
	} else {
		daddrOffset = 24
		daddrLen = 16
		fam = unix.NFPROTO_IPV6
	}

	snatRule := &nftables.Rule{
		Table: nat,
		Chain: postRoutingCh,
		Exprs: []expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       daddrOffset,
				Len:          daddrLen,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     dst.AsSlice(),
			},
			&expr.Immediate{
				Register: 1,
				Data:     src.AsSlice(),
			},
			&expr.NAT{
				Type:       expr.NATTypeSourceNAT,
				Family:     fam,
				RegAddrMin: 1,
			},
		},
	}
	n.conn.AddRule(snatRule)
	return n.conn.Flush()
}

func (n *nftablesRunner) ClampMSSToPMTU(tun string, addr netip.Addr) error {
	polAccept := nftables.ChainPolicyAccept
	table := n.getNFTByAddr(addr)
	filterTable, err := createTableIfNotExist(n.conn, table.Proto, "filter")
	if err != nil {
		return fmt.Errorf("error ensuring filter table: %w", err)
	}

	// ensure forwarding chain exists
	fwChain, err := getOrCreateChain(n.conn, chainInfo{
		table:         filterTable,
		name:          "FORWARD",
		chainType:     nftables.ChainTypeFilter,
		chainHook:     nftables.ChainHookForward,
		chainPriority: nftables.ChainPriorityFilter,
		chainPolicy:   &polAccept,
	})
	if err != nil {
		return fmt.Errorf("error ensuring forward chain: %w", err)
	}

	clampRule := &nftables.Rule{
		Table: filterTable,
		Chain: fwChain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte(tun),
			},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_TCP},
			},
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       13,
				Len:          1,
			},
			&expr.Bitwise{
				DestRegister:   1,
				SourceRegister: 1,
				Len:            1,
				Mask:           []byte{0x02},
				Xor:            []byte{0x00},
			},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     []byte{0x00},
			},
			&expr.Rt{
				Register: 1,
				Key:      expr.RtTCPMSS,
			},
			&expr.Byteorder{
				DestRegister:   1,
				SourceRegister: 1,
				Op:             expr.ByteorderHton,
				Len:            2,
				Size:           2,
			},
			&expr.Exthdr{
				SourceRegister: 1,
				Type:           2,
				Offset:         2,
				Len:            2,
				Op:             expr.ExthdrOpTcpopt,
			},
		},
	}
	n.conn.AddRule(clampRule)
	return n.conn.Flush()
}

// deleteTableIfExists deletes a nftables table via connection c if it exists
// within the given family.
func deleteTableIfExists(c *nftables.Conn, family nftables.TableFamily, name string) error {
	t, err := getTableIfExists(c, family, name)
	if err != nil {
		return fmt.Errorf("get table: %w", err)
	}
	if t == nil {
		// Table does not exist, so nothing to delete.
		return nil
	}
	c.DelTable(t)
	if err := c.Flush(); err != nil {
		if t, err = getTableIfExists(c, family, name); t == nil && err == nil {
			// Check if the table still exists. If it does not, then the error
			// is due to the table not existing, so we can ignore it. Maybe a
			// concurrent process deleted the table.
			return nil
		}
		return fmt.Errorf("del table: %w", err)
	}
	return nil
}

// getTableIfExists returns the table with the given name from the given family
// if it exists. If none match, it returns (nil, nil).
func getTableIfExists(c *nftables.Conn, family nftables.TableFamily, name string) (*nftables.Table, error) {
	tables, err := c.ListTables()
	if err != nil {
		return nil, fmt.Errorf("get tables: %w", err)
	}
	for _, table := range tables {
		if table.Name == name && table.Family == family {
			return table, nil
		}
	}
	return nil, nil
}

// createTableIfNotExist creates a nftables table via connection c if it does
// not exist within the given family.
func createTableIfNotExist(c *nftables.Conn, family nftables.TableFamily, name string) (*nftables.Table, error) {
	if t, err := getTableIfExists(c, family, name); err != nil {
		return nil, fmt.Errorf("get table: %w", err)
	} else if t != nil {
		return t, nil
	}
	t := c.AddTable(&nftables.Table{
		Family: family,
		Name:   name,
	})
	if err := c.Flush(); err != nil {
		return nil, fmt.Errorf("add table: %w", err)
	}
	return t, nil
}

type errorChainNotFound struct {
	chainName string
	tableName string
}

func (e errorChainNotFound) Error() string {
	return fmt.Sprintf("chain %s not found in table %s", e.chainName, e.tableName)
}

// getChainFromTable returns the chain with the given name from the given table.
// Note that a chain name is unique within a table.
func getChainFromTable(c *nftables.Conn, table *nftables.Table, name string) (*nftables.Chain, error) {
	chains, err := c.ListChainsOfTableFamily(table.Family)
	if err != nil {
		return nil, fmt.Errorf("list chains: %w", err)
	}

	for _, chain := range chains {
		// Table family is already checked so table name is unique
		if chain.Table.Name == table.Name && chain.Name == name {
			return chain, nil
		}
	}

	return nil, errorChainNotFound{table.Name, name}
}

// isTSChain reports whether `name` begins with "ts-" (and is thus a
// Tailscale-managed chain).
func isTSChain(name string) bool {
	return strings.HasPrefix(name, "ts-")
}

// createChainIfNotExist creates a chain with the given name in the given table
// if it does not exist.
func createChainIfNotExist(c *nftables.Conn, cinfo chainInfo) error {
	_, err := getOrCreateChain(c, cinfo)
	return err
}

func getOrCreateChain(c *nftables.Conn, cinfo chainInfo) (*nftables.Chain, error) {
	chain, err := getChainFromTable(c, cinfo.table, cinfo.name)
	if err != nil && !errors.Is(err, errorChainNotFound{cinfo.table.Name, cinfo.name}) {
		return nil, fmt.Errorf("get chain: %w", err)
	} else if err == nil {
		// The chain already exists. If it is a TS chain, check the
		// type/hook/priority, but for "conventional chains" assume they're what
		// we expect (in case iptables-nft/ufw make minor behavior changes in
		// the future).
		if isTSChain(chain.Name) && (chain.Type != cinfo.chainType || chain.Hooknum != cinfo.chainHook || chain.Priority != cinfo.chainPriority) {
			return nil, fmt.Errorf("chain %s already exists with different type/hook/priority", cinfo.name)
		}
		return chain, nil
	}

	chain = c.AddChain(&nftables.Chain{
		Name:     cinfo.name,
		Table:    cinfo.table,
		Type:     cinfo.chainType,
		Hooknum:  cinfo.chainHook,
		Priority: cinfo.chainPriority,
		Policy:   cinfo.chainPolicy,
	})

	if err := c.Flush(); err != nil {
		return nil, fmt.Errorf("add chain: %w", err)
	}

	return chain, nil
}

// NetfilterRunner abstracts helpers to run netfilter commands. It is
// implemented by linuxfw.IPTablesRunner and linuxfw.NfTablesRunner.
type NetfilterRunner interface {
	// AddLoopbackRule adds a rule to permit loopback traffic to addr. This rule
	// is added only if it does not already exist.
	AddLoopbackRule(addr netip.Addr) error

	// DelLoopbackRule removes the rule added by AddLoopbackRule.
	DelLoopbackRule(addr netip.Addr) error

	// AddHooks adds rules to conventional chains like "FORWARD", "INPUT" and
	// "POSTROUTING" to jump from those chains to tailscale chains.
	AddHooks() error

	// DelHooks deletes rules added by AddHooks.
	DelHooks(logf logger.Logf) error

	// AddChains creates custom Tailscale chains.
	AddChains() error

	// DelChains removes chains added by AddChains.
	DelChains() error

	// AddBase adds rules reused by different other rules.
	AddBase(tunname string) error

	// DelBase removes rules added by AddBase.
	DelBase() error

	// AddSNATRule adds the netfilter rule to SNAT incoming traffic over
	// the Tailscale interface destined for local subnets. An error is
	// returned if the rule already exists.
	AddSNATRule() error

	// DelSNATRule removes the rule added by AddSNATRule.
	DelSNATRule() error

	// HasIPV6 reports true if the system supports IPv6.
	HasIPV6() bool

	// HasIPV6NAT reports true if the system supports IPv6 NAT.
	HasIPV6NAT() bool

	// AddDNATRule adds a rule to the nat/PREROUTING chain to DNAT traffic
	// destined for the given original destination to the given new destination.
	// This is used to forward all traffic destined for the Tailscale interface
	// to the provided destination, as used in the Kubernetes ingress proxies.
	AddDNATRule(origDst, dst netip.Addr) error

	// AddSNATRuleForDst adds a rule to the nat/POSTROUTING chain to SNAT
	// traffic destined for dst to src.
	// This is used to forward traffic destined for the local machine over
	// the Tailscale interface, as used in the Kubernetes egress proxies.
	AddSNATRuleForDst(src, dst netip.Addr) error

	// DNATNonTailscaleTraffic adds a rule to the nat/PREROUTING chain to DNAT
	// all traffic inbound from any interface except exemptInterface to dst.
	// This is used to forward traffic destined for the local machine over
	// the Tailscale interface, as used in the Kubernetes egress proxies.//
	DNATNonTailscaleTraffic(exemptInterface string, dst netip.Addr) error

	// ClampMSSToPMTU adds a rule to the mangle/FORWARD chain to clamp MSS for
	// traffic destined for the provided tun interface.
	ClampMSSToPMTU(tun string, addr netip.Addr) error

	// AddMagicsockPortRule adds a rule to the ts-input chain to accept
	// incoming traffic on the specified port, to allow magicsock to
	// communicate.
	AddMagicsockPortRule(port uint16, network string) error

	// DelMagicsockPortRule removes the rule created by AddMagicsockPortRule,
	// if it exists.
	DelMagicsockPortRule(port uint16, network string) error
}

// New creates a NetfilterRunner, auto-detecting whether to use
// nftables or iptables.
// As nftables is still experimental, iptables will be used unless
// either the TS_DEBUG_FIREWALL_MODE environment variable, or the prefHint
// parameter, is set to one of "nftables" or "auto".
func New(logf logger.Logf, prefHint string) (NetfilterRunner, error) {
	mode := detectFirewallMode(logf, prefHint)
	switch mode {
	case FirewallModeIPTables:
		return newIPTablesRunner(logf)
	case FirewallModeNfTables:
		return newNfTablesRunner(logf)
	default:
		return nil, fmt.Errorf("unknown firewall mode %v", mode)
	}
}

// newNfTablesRunner creates a new nftablesRunner without guaranteeing
// the existence of the tables and chains.
func newNfTablesRunner(logf logger.Logf) (*nftablesRunner, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("nftables connection: %w", err)
	}
	nft4 := &nftable{Proto: nftables.TableFamilyIPv4}

	v6err := checkIPv6(logf)
	if v6err != nil {
		logf("disabling tunneled IPv6 due to system IPv6 config: %v", v6err)
	}
	supportsV6 := v6err == nil
	var nft6 *nftable

	if supportsV6 {
		nft6 = &nftable{Proto: nftables.TableFamilyIPv6}
		// Kernel support for nftables was added after support for IPv6
		// NAT, so no need for a separate IPv6 NAT support check.
		// https://tldp.org/HOWTO/Linux+IPv6-HOWTO/ch18s04.html
		// https://wiki.nftables.org/wiki-nftables/index.php/Building_and_installing_nftables_from_sources
		logf("v6nat availability: true")
	}

	// TODO(KevinLiang10): convert iptables rule to nftable rules if they exist in the iptables

	return &nftablesRunner{
		conn:           conn,
		nft4:           nft4,
		nft6:           nft6,
		v6Available:    supportsV6,
		v6NATAvailable: supportsV6, // if nftables are supported, IPv6 NAT is supported
	}, nil
}

// newLoadSaddrExpr creates a new nftables expression that loads the source
// address of the packet into the given register.
func newLoadSaddrExpr(proto nftables.TableFamily, destReg uint32) (expr.Any, error) {
	switch proto {
	case nftables.TableFamilyIPv4:
		return &expr.Payload{
			DestRegister: destReg,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       12,
			Len:          4,
		}, nil
	case nftables.TableFamilyIPv6:
		return &expr.Payload{
			DestRegister: destReg,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       8,
			Len:          16,
		}, nil
	default:
		return nil, fmt.Errorf("table family %v is neither IPv4 nor IPv6", proto)
	}
}

// newLoadDportExpr creates a new nftables express that loads the desination port
// of a TCP/UDP packet into the given register.
func newLoadDportExpr(destReg uint32) expr.Any {
	return &expr.Payload{
		DestRegister: destReg,
		Base:         expr.PayloadBaseTransportHeader,
		Offset:       2,
		Len:          2,
	}
}

// HasIPV6 reports true if the system supports IPv6.
func (n *nftablesRunner) HasIPV6() bool {
	return n.v6Available
}

// HasIPV6NAT returns true if the system supports IPv6 NAT.
func (n *nftablesRunner) HasIPV6NAT() bool {
	return n.v6NATAvailable
}

// findRule iterates through the rules to find the rule with matching expressions.
func findRule(conn *nftables.Conn, rule *nftables.Rule) (*nftables.Rule, error) {
	rules, err := conn.GetRules(rule.Table, rule.Chain)
	if err != nil {
		return nil, fmt.Errorf("get nftables rules: %w", err)
	}
	if len(rules) == 0 {
		return nil, nil
	}

ruleLoop:
	for _, r := range rules {
		if len(r.Exprs) != len(rule.Exprs) {
			continue
		}

		for i, e := range r.Exprs {
			// Skip counter expressions, as they will not match.
			if _, ok := e.(*expr.Counter); ok {
				continue
			}
			if !reflect.DeepEqual(e, rule.Exprs[i]) {
				continue ruleLoop
			}
		}
		return r, nil
	}

	return nil, nil
}

func createLoopbackRule(
	proto nftables.TableFamily,
	table *nftables.Table,
	chain *nftables.Chain,
	addr netip.Addr,
) (*nftables.Rule, error) {
	saddrExpr, err := newLoadSaddrExpr(proto, 1)
	if err != nil {
		return nil, fmt.Errorf("newLoadSaddrExpr: %w", err)
	}
	loopBackRule := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{
				Key:      expr.MetaKeyIIFNAME,
				Register: 1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte("lo"),
			},
			saddrExpr,
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     addr.AsSlice(),
			},
			&expr.Counter{},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	}
	return loopBackRule, nil
}

// insertLoopbackRule inserts the TS loop back rule into
// the given chain as the first rule if it does not exist.
func insertLoopbackRule(
	conn *nftables.Conn, proto nftables.TableFamily,
	table *nftables.Table, chain *nftables.Chain, addr netip.Addr) error {

	loopBackRule, err := createLoopbackRule(proto, table, chain, addr)
	if err != nil {
		return fmt.Errorf("create loopback rule: %w", err)
	}

	// If TestDial is set, we are running in test mode and we should not
	// find rule because header will mismatch.
	if conn.TestDial == nil {
		// Check if the rule already exists.
		rule, err := findRule(conn, loopBackRule)
		if err != nil {
			return fmt.Errorf("find rule: %w", err)
		}
		if rule != nil {
			// Rule already exists, no need to insert.
			return nil
		}
	}

	// This inserts the rule to the top of the chain
	_ = conn.InsertRule(loopBackRule)

	if err = conn.Flush(); err != nil {
		return fmt.Errorf("insert rule: %w", err)
	}
	return nil
}

// getNFTByAddr returns the nftables with correct IP family
// that we will be using for the given address.
func (n *nftablesRunner) getNFTByAddr(addr netip.Addr) *nftable {
	if addr.Is6() {
		return n.nft6
	}
	return n.nft4
}

// AddLoopbackRule adds an nftables rule to permit loopback traffic to
// a local Tailscale IP. This rule is added only if it does not already exist.
func (n *nftablesRunner) AddLoopbackRule(addr netip.Addr) error {
	nf := n.getNFTByAddr(addr)

	inputChain, err := getChainFromTable(n.conn, nf.Filter, chainNameInput)
	if err != nil {
		return fmt.Errorf("get input chain: %w", err)
	}

	if err := insertLoopbackRule(n.conn, nf.Proto, nf.Filter, inputChain, addr); err != nil {
		return fmt.Errorf("add loopback rule: %w", err)
	}

	return nil
}

// DelLoopbackRule removes the nftables rule permitting loopback
// traffic to a Tailscale IP.
func (n *nftablesRunner) DelLoopbackRule(addr netip.Addr) error {
	nf := n.getNFTByAddr(addr)

	inputChain, err := getChainFromTable(n.conn, nf.Filter, chainNameInput)
	if err != nil {
		return fmt.Errorf("get input chain: %w", err)
	}

	loopBackRule, err := createLoopbackRule(nf.Proto, nf.Filter, inputChain, addr)
	if err != nil {
		return fmt.Errorf("create loopback rule: %w", err)
	}

	existingLoopBackRule, err := findRule(n.conn, loopBackRule)
	if err != nil {
		return fmt.Errorf("find loop back rule: %w", err)
	}
	if existingLoopBackRule == nil {
		// Rule does not exist, no need to delete.
		return nil
	}

	if err := n.conn.DelRule(existingLoopBackRule); err != nil {
		return fmt.Errorf("delete rule: %w", err)
	}

	return n.conn.Flush()
}

// getTables gets the available nftable in nftables runner.
func (n *nftablesRunner) getTables() []*nftable {
	if n.v6Available {
		return []*nftable{n.nft4, n.nft6}
	}
	return []*nftable{n.nft4}
}

// getNATTables gets the available nftable in nftables runner.
// If the system does not support IPv6 NAT, only the IPv4 nftable
// will be returned.
func (n *nftablesRunner) getNATTables() []*nftable {
	if n.v6NATAvailable {
		return n.getTables()
	}
	return []*nftable{n.nft4}
}

// AddChains creates custom Tailscale chains in netfilter via nftables
// if the ts-chain doesn't already exist.
func (n *nftablesRunner) AddChains() error {
	polAccept := nftables.ChainPolicyAccept
	for _, table := range n.getTables() {
		// Create the filter table if it doesn't exist, this table name is the same
		// as the name used by iptables-nft and ufw. We install rules into the
		// same conventional table so that `accept` verdicts from our jump
		// chains are conclusive.
		filter, err := createTableIfNotExist(n.conn, table.Proto, "filter")
		if err != nil {
			return fmt.Errorf("create table: %w", err)
		}
		table.Filter = filter
		// Adding the "conventional chains" that are used by iptables-nft and ufw.
		if err = createChainIfNotExist(n.conn, chainInfo{filter, "FORWARD", nftables.ChainTypeFilter, nftables.ChainHookForward, nftables.ChainPriorityFilter, &polAccept}); err != nil {
			return fmt.Errorf("create forward chain: %w", err)
		}
		if err = createChainIfNotExist(n.conn, chainInfo{filter, "INPUT", nftables.ChainTypeFilter, nftables.ChainHookInput, nftables.ChainPriorityFilter, &polAccept}); err != nil {
			return fmt.Errorf("create input chain: %w", err)
		}
		// Adding the tailscale chains that contain our rules.
		if err = createChainIfNotExist(n.conn, chainInfo{filter, chainNameForward, chainTypeRegular, nil, nil, nil}); err != nil {
			return fmt.Errorf("create forward chain: %w", err)
		}
		if err = createChainIfNotExist(n.conn, chainInfo{filter, chainNameInput, chainTypeRegular, nil, nil, nil}); err != nil {
			return fmt.Errorf("create input chain: %w", err)
		}
	}

	for _, table := range n.getNATTables() {
		// Create the nat table if it doesn't exist, this table name is the same
		// as the name used by iptables-nft and ufw. We install rules into the
		// same conventional table so that `accept` verdicts from our jump
		// chains are conclusive.
		nat, err := createTableIfNotExist(n.conn, table.Proto, "nat")
		if err != nil {
			return fmt.Errorf("create table: %w", err)
		}
		table.Nat = nat
		// Adding the "conventional chains" that are used by iptables-nft and ufw.
		if err = createChainIfNotExist(n.conn, chainInfo{nat, "POSTROUTING", nftables.ChainTypeNAT, nftables.ChainHookPostrouting, nftables.ChainPriorityNATSource, &polAccept}); err != nil {
			return fmt.Errorf("create postrouting chain: %w", err)
		}
		// Adding the tailscale chain that contains our rules.
		if err = createChainIfNotExist(n.conn, chainInfo{nat, chainNamePostrouting, chainTypeRegular, nil, nil, nil}); err != nil {
			return fmt.Errorf("create postrouting chain: %w", err)
		}
	}

	return n.conn.Flush()
}

// These are dummy chains and tables we create to detect if nftables is
// available. We create them, then delete them. If we can create and delete
// them, then we can use nftables. If we can't, then we assume that we're
// running on a system that doesn't support nftables. See
// createDummyPostroutingChains.
const (
	tsDummyChainName = "ts-test-postrouting"
	tsDummyTableName = "ts-test-nat"
)

// createDummyPostroutingChains creates dummy postrouting chains in netfilter
// via netfilter via nftables, as a last resort measure to detect that nftables
// can be used. It cleans up the dummy chains after creation.
func (n *nftablesRunner) createDummyPostroutingChains() (retErr error) {
	polAccept := ptr.To(nftables.ChainPolicyAccept)
	for _, table := range n.getNATTables() {
		nat, err := createTableIfNotExist(n.conn, table.Proto, tsDummyTableName)
		if err != nil {
			return fmt.Errorf("create nat table: %w", err)
		}
		defer func(fm nftables.TableFamily) {
			if err := deleteTableIfExists(n.conn, fm, tsDummyTableName); err != nil && retErr == nil {
				retErr = fmt.Errorf("delete %q table: %w", tsDummyTableName, err)
			}
		}(table.Proto)

		table.Nat = nat
		if err = createChainIfNotExist(n.conn, chainInfo{nat, tsDummyChainName, nftables.ChainTypeNAT, nftables.ChainHookPostrouting, nftables.ChainPriorityNATSource, polAccept}); err != nil {
			return fmt.Errorf("create %q chain: %w", tsDummyChainName, err)
		}
		if err := deleteChainIfExists(n.conn, nat, tsDummyChainName); err != nil {
			return fmt.Errorf("delete %q chain: %w", tsDummyChainName, err)
		}
	}
	return nil
}

// deleteChainIfExists deletes a chain if it exists.
func deleteChainIfExists(c *nftables.Conn, table *nftables.Table, name string) error {
	chain, err := getChainFromTable(c, table, name)
	if err != nil && !errors.Is(err, errorChainNotFound{table.Name, name}) {
		return fmt.Errorf("get chain: %w", err)
	} else if err != nil {
		// If the chain doesn't exist, we don't need to delete it.
		return nil
	}

	c.FlushChain(chain)
	c.DelChain(chain)

	if err := c.Flush(); err != nil {
		return fmt.Errorf("flush and delete chain: %w", err)
	}

	return nil
}

// DelChains removes the custom Tailscale chains from netfilter via nftables.
func (n *nftablesRunner) DelChains() error {
	for _, table := range n.getTables() {
		if err := deleteChainIfExists(n.conn, table.Filter, chainNameForward); err != nil {
			return fmt.Errorf("delete chain: %w", err)
		}
		if err := deleteChainIfExists(n.conn, table.Filter, chainNameInput); err != nil {
			return fmt.Errorf("delete chain: %w", err)
		}
	}

	if err := deleteChainIfExists(n.conn, n.nft4.Nat, chainNamePostrouting); err != nil {
		return fmt.Errorf("delete chain: %w", err)
	}

	if n.v6NATAvailable {
		if err := deleteChainIfExists(n.conn, n.nft6.Nat, chainNamePostrouting); err != nil {
			return fmt.Errorf("delete chain: %w", err)
		}
	}

	if err := n.conn.Flush(); err != nil {
		return fmt.Errorf("flush: %w", err)
	}

	return nil
}

// createHookRule creates a rule to jump from a hooked chain to a regular chain.
func createHookRule(table *nftables.Table, fromChain *nftables.Chain, toChainName string) *nftables.Rule {
	exprs := []expr.Any{
		&expr.Counter{},
		&expr.Verdict{
			Kind:  expr.VerdictJump,
			Chain: toChainName,
		},
	}

	rule := &nftables.Rule{
		Table: table,
		Chain: fromChain,
		Exprs: exprs,
	}

	return rule
}

// addHookRule adds a rule to jump from a hooked chain to a regular chain at top of the hooked chain.
func addHookRule(conn *nftables.Conn, table *nftables.Table, fromChain *nftables.Chain, toChainName string) error {
	rule := createHookRule(table, fromChain, toChainName)
	_ = conn.InsertRule(rule)

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("flush add rule: %w", err)
	}

	return nil
}

// AddHooks is adding rules to conventional chains like "FORWARD", "INPUT" and "POSTROUTING"
// in tables and jump from those chains to tailscale chains.
func (n *nftablesRunner) AddHooks() error {
	conn := n.conn

	for _, table := range n.getTables() {
		inputChain, err := getChainFromTable(conn, table.Filter, "INPUT")
		if err != nil {
			return fmt.Errorf("get INPUT chain: %w", err)
		}
		err = addHookRule(conn, table.Filter, inputChain, chainNameInput)
		if err != nil {
			return fmt.Errorf("Addhook: %w", err)
		}
		forwardChain, err := getChainFromTable(conn, table.Filter, "FORWARD")
		if err != nil {
			return fmt.Errorf("get FORWARD chain: %w", err)
		}
		err = addHookRule(conn, table.Filter, forwardChain, chainNameForward)
		if err != nil {
			return fmt.Errorf("Addhook: %w", err)
		}
	}

	for _, table := range n.getNATTables() {
		postroutingChain, err := getChainFromTable(conn, table.Nat, "POSTROUTING")
		if err != nil {
			return fmt.Errorf("get INPUT chain: %w", err)
		}
		err = addHookRule(conn, table.Nat, postroutingChain, chainNamePostrouting)
		if err != nil {
			return fmt.Errorf("Addhook: %w", err)
		}
	}
	return nil
}

// delHookRule deletes a rule that jumps from a hooked chain to a regular chain.
func delHookRule(conn *nftables.Conn, table *nftables.Table, fromChain *nftables.Chain, toChainName string) error {
	rule := createHookRule(table, fromChain, toChainName)
	existingRule, err := findRule(conn, rule)
	if err != nil {
		return fmt.Errorf("Failed to find hook rule: %w", err)
	}

	if existingRule == nil {
		return nil
	}

	_ = conn.DelRule(existingRule)

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("flush del hook rule: %w", err)
	}
	return nil
}

// DelHooks is deleting the rules added to conventional chains to jump to tailscale chains.
func (n *nftablesRunner) DelHooks(logf logger.Logf) error {
	conn := n.conn

	for _, table := range n.getTables() {
		inputChain, err := getChainFromTable(conn, table.Filter, "INPUT")
		if err != nil {
			return fmt.Errorf("get INPUT chain: %w", err)
		}
		err = delHookRule(conn, table.Filter, inputChain, chainNameInput)
		if err != nil {
			return fmt.Errorf("delhook: %w", err)
		}
		forwardChain, err := getChainFromTable(conn, table.Filter, "FORWARD")
		if err != nil {
			return fmt.Errorf("get FORWARD chain: %w", err)
		}
		err = delHookRule(conn, table.Filter, forwardChain, chainNameForward)
		if err != nil {
			return fmt.Errorf("delhook: %w", err)
		}
	}

	for _, table := range n.getNATTables() {
		postroutingChain, err := getChainFromTable(conn, table.Nat, "POSTROUTING")
		if err != nil {
			return fmt.Errorf("get INPUT chain: %w", err)
		}
		err = delHookRule(conn, table.Nat, postroutingChain, chainNamePostrouting)
		if err != nil {
			return fmt.Errorf("delhook: %w", err)
		}
	}

	return nil
}

// maskof returns the mask of the given prefix in big endian bytes.
func maskof(pfx netip.Prefix) []byte {
	mask := make([]byte, 4)
	binary.BigEndian.PutUint32(mask, ^(uint32(0xffff_ffff) >> pfx.Bits()))
	return mask
}

// createRangeRule creates a rule that matches packets with source IP from the give
// range (like CGNAT range or ChromeOSVM range) and the interface is not the tunname,
// and makes the given decision. Only IPv4 is supported.
func createRangeRule(
	table *nftables.Table, chain *nftables.Chain,
	tunname string, rng netip.Prefix, decision expr.VerdictKind,
) (*nftables.Rule, error) {
	if rng.Addr().Is6() {
		return nil, errors.New("IPv6 is not supported")
	}
	saddrExpr, err := newLoadSaddrExpr(nftables.TableFamilyIPv4, 1)
	if err != nil {
		return nil, fmt.Errorf("newLoadSaddrExpr: %w", err)
	}
	netip := rng.Addr().AsSlice()
	mask := maskof(rng)
	rule := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     []byte(tunname),
			},
			saddrExpr,
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           mask,
				Xor:            []byte{0x00, 0x00, 0x00, 0x00},
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     netip,
			},
			&expr.Counter{},
			&expr.Verdict{
				Kind: decision,
			},
		},
	}
	return rule, nil

}

// addReturnChromeOSVMRangeRule adds a rule to return if the source IP
// is in the ChromeOS VM range.
func addReturnChromeOSVMRangeRule(c *nftables.Conn, table *nftables.Table, chain *nftables.Chain, tunname string) error {
	rule, err := createRangeRule(table, chain, tunname, tsaddr.ChromeOSVMRange(), expr.VerdictReturn)
	if err != nil {
		return fmt.Errorf("create rule: %w", err)
	}
	_ = c.AddRule(rule)
	if err = c.Flush(); err != nil {
		return fmt.Errorf("add rule: %w", err)
	}
	return nil
}

// addDropCGNATRangeRule adds a rule to drop if the source IP is in the
// CGNAT range.
func addDropCGNATRangeRule(c *nftables.Conn, table *nftables.Table, chain *nftables.Chain, tunname string) error {
	rule, err := createRangeRule(table, chain, tunname, tsaddr.CGNATRange(), expr.VerdictDrop)
	if err != nil {
		return fmt.Errorf("create rule: %w", err)
	}
	_ = c.AddRule(rule)
	if err = c.Flush(); err != nil {
		return fmt.Errorf("add rule: %w", err)
	}
	return nil
}

// createSetSubnetRouteMarkRule creates a rule to set the subnet route
// mark if the packet is from the given interface.
func createSetSubnetRouteMarkRule(table *nftables.Table, chain *nftables.Chain, tunname string) (*nftables.Rule, error) {
	hexTsFwmarkMaskNeg := getTailscaleFwmarkMaskNeg()
	hexTSSubnetRouteMark := getTailscaleSubnetRouteMark()

	rule := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte(tunname),
			},
			&expr.Counter{},
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           hexTsFwmarkMaskNeg,
				Xor:            hexTSSubnetRouteMark,
			},
			&expr.Meta{
				Key:            expr.MetaKeyMARK,
				SourceRegister: true,
				Register:       1,
			},
		},
	}
	return rule, nil
}

// addSetSubnetRouteMarkRule adds a rule to set the subnet route mark
// if the packet is from the given interface.
func addSetSubnetRouteMarkRule(c *nftables.Conn, table *nftables.Table, chain *nftables.Chain, tunname string) error {
	rule, err := createSetSubnetRouteMarkRule(table, chain, tunname)
	if err != nil {
		return fmt.Errorf("create rule: %w", err)
	}
	_ = c.AddRule(rule)

	if err := c.Flush(); err != nil {
		return fmt.Errorf("add rule: %w", err)
	}

	return nil
}

// createDropOutgoingPacketFromCGNATRangeRuleWithTunname creates a rule to drop
// outgoing packets from the CGNAT range.
func createDropOutgoingPacketFromCGNATRangeRuleWithTunname(table *nftables.Table, chain *nftables.Chain, tunname string) (*nftables.Rule, error) {
	_, ipNet, err := net.ParseCIDR(tsaddr.CGNATRange().String())
	if err != nil {
		return nil, fmt.Errorf("parse cidr: %v", err)
	}
	mask, err := hex.DecodeString(ipNet.Mask.String())
	if err != nil {
		return nil, fmt.Errorf("decode mask: %v", err)
	}
	netip := ipNet.IP.Mask(ipNet.Mask).To4()
	saddrExpr, err := newLoadSaddrExpr(nftables.TableFamilyIPv4, 1)
	if err != nil {
		return nil, fmt.Errorf("newLoadSaddrExpr: %v", err)
	}
	rule := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte(tunname),
			},
			saddrExpr,
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           mask,
				Xor:            []byte{0x00, 0x00, 0x00, 0x00},
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     netip,
			},
			&expr.Counter{},
			&expr.Verdict{
				Kind: expr.VerdictDrop,
			},
		},
	}
	return rule, nil
}

// addDropOutgoingPacketFromCGNATRangeRuleWithTunname adds a rule to drop
// outgoing packets from the CGNAT range.
func addDropOutgoingPacketFromCGNATRangeRuleWithTunname(conn *nftables.Conn, table *nftables.Table, chain *nftables.Chain, tunname string) error {
	rule, err := createDropOutgoingPacketFromCGNATRangeRuleWithTunname(table, chain, tunname)
	if err != nil {
		return fmt.Errorf("create rule: %w", err)
	}
	_ = conn.AddRule(rule)

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("add rule: %w", err)
	}
	return nil
}

// createAcceptOutgoingPacketRule creates a rule to accept outgoing packets
// from the given interface.
func createAcceptOutgoingPacketRule(table *nftables.Table, chain *nftables.Chain, tunname string) *nftables.Rule {
	return &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte(tunname),
			},
			&expr.Counter{},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	}
}

// addAcceptOutgoingPacketRule adds a rule to accept outgoing packets
// from the given interface.
func addAcceptOutgoingPacketRule(conn *nftables.Conn, table *nftables.Table, chain *nftables.Chain, tunname string) error {
	rule := createAcceptOutgoingPacketRule(table, chain, tunname)
	_ = conn.AddRule(rule)

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("flush add rule: %w", err)
	}

	return nil
}

// createAcceptOnPortRule creates a rule to accept incoming packets to
// a given destination UDP port.
func createAcceptOnPortRule(table *nftables.Table, chain *nftables.Chain, port uint16) *nftables.Rule {
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	return &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{
				Key:      expr.MetaKeyL4PROTO,
				Register: 1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_UDP},
			},
			newLoadDportExpr(1),
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     portBytes,
			},
			&expr.Counter{},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	}
}

// addAcceptOnPortRule adds a rule to accept incoming packets to
// a given destination UDP port.
func addAcceptOnPortRule(conn *nftables.Conn, table *nftables.Table, chain *nftables.Chain, port uint16) error {
	rule := createAcceptOnPortRule(table, chain, port)
	_ = conn.AddRule(rule)

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("flush add rule: %w", err)
	}

	return nil
}

// addAcceptOnPortRule removes a rule to accept incoming packets to
// a given destination UDP port.
func removeAcceptOnPortRule(conn *nftables.Conn, table *nftables.Table, chain *nftables.Chain, port uint16) error {
	rule := createAcceptOnPortRule(table, chain, port)
	rule, err := findRule(conn, rule)
	if err != nil {
		return fmt.Errorf("find rule: %v", err)
	}

	_ = conn.DelRule(rule)

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("flush del rule: %w", err)
	}

	return nil
}

// AddMagicsockPortRule adds a rule to nftables to allow incoming traffic on
// the specified UDP port, so magicsock can accept incoming connections.
// network must be either "udp4" or "udp6" - this determines whether the rule
// is added for IPv4 or IPv6.
func (n *nftablesRunner) AddMagicsockPortRule(port uint16, network string) error {
	var filterTable *nftables.Table
	switch network {
	case "udp4":
		filterTable = n.nft4.Filter
	case "udp6":
		filterTable = n.nft6.Filter
	default:
		return fmt.Errorf("unsupported network %s", network)
	}

	inputChain, err := getChainFromTable(n.conn, filterTable, chainNameInput)
	if err != nil {
		return fmt.Errorf("get input chain: %v", err)
	}

	err = addAcceptOnPortRule(n.conn, filterTable, inputChain, port)
	if err != nil {
		return fmt.Errorf("add accept on port rule: %v", err)
	}

	return nil
}

// DelMagicsockPortRule removes a rule added by AddMagicsockPortRule to accept
// incoming traffic on a particular UDP port.
// network must be either "udp4" or "udp6" - this determines whether the rule
// is removed for IPv4 or IPv6.
func (n *nftablesRunner) DelMagicsockPortRule(port uint16, network string) error {
	var filterTable *nftables.Table
	switch network {
	case "udp4":
		filterTable = n.nft4.Filter
	case "udp6":
		filterTable = n.nft6.Filter
	default:
		return fmt.Errorf("unsupported network %s", network)
	}

	inputChain, err := getChainFromTable(n.conn, filterTable, chainNameInput)
	if err != nil {
		return fmt.Errorf("get input chain: %v", err)
	}

	err = removeAcceptOnPortRule(n.conn, filterTable, inputChain, port)
	if err != nil {
		return fmt.Errorf("add accept on port rule: %v", err)
	}

	return nil
}

// createAcceptIncomingPacketRule creates a rule to accept incoming packets to
// the given interface.
func createAcceptIncomingPacketRule(table *nftables.Table, chain *nftables.Chain, tunname string) *nftables.Rule {
	return &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte(tunname),
			},
			&expr.Counter{},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	}
}

func addAcceptIncomingPacketRule(conn *nftables.Conn, table *nftables.Table, chain *nftables.Chain, tunname string) error {
	rule := createAcceptIncomingPacketRule(table, chain, tunname)
	_ = conn.AddRule(rule)

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("flush add rule: %w", err)
	}

	return nil
}

// AddBase adds some basic processing rules.
func (n *nftablesRunner) AddBase(tunname string) error {
	if err := n.addBase4(tunname); err != nil {
		return fmt.Errorf("add base v4: %w", err)
	}
	if n.HasIPV6() {
		if err := n.addBase6(tunname); err != nil {
			return fmt.Errorf("add base v6: %w", err)
		}
	}
	return nil
}

// addBase4 adds some basic IPv4 processing rules.
func (n *nftablesRunner) addBase4(tunname string) error {
	conn := n.conn

	inputChain, err := getChainFromTable(conn, n.nft4.Filter, chainNameInput)
	if err != nil {
		return fmt.Errorf("get input chain v4: %v", err)
	}
	if err = addReturnChromeOSVMRangeRule(conn, n.nft4.Filter, inputChain, tunname); err != nil {
		return fmt.Errorf("add return chromeos vm range rule v4: %w", err)
	}
	if err = addDropCGNATRangeRule(conn, n.nft4.Filter, inputChain, tunname); err != nil {
		return fmt.Errorf("add drop cgnat range rule v4: %w", err)
	}
	if err = addAcceptIncomingPacketRule(conn, n.nft4.Filter, inputChain, tunname); err != nil {
		return fmt.Errorf("add accept incoming packet rule v4: %w", err)
	}

	forwardChain, err := getChainFromTable(conn, n.nft4.Filter, chainNameForward)
	if err != nil {
		return fmt.Errorf("get forward chain v4: %v", err)
	}

	if err = addSetSubnetRouteMarkRule(conn, n.nft4.Filter, forwardChain, tunname); err != nil {
		return fmt.Errorf("add set subnet route mark rule v4: %w", err)
	}

	if err = addMatchSubnetRouteMarkRule(conn, n.nft4.Filter, forwardChain, Accept); err != nil {
		return fmt.Errorf("add match subnet route mark rule v4: %w", err)
	}

	if err = addDropOutgoingPacketFromCGNATRangeRuleWithTunname(conn, n.nft4.Filter, forwardChain, tunname); err != nil {
		return fmt.Errorf("add drop outgoing packet from cgnat range rule v4: %w", err)
	}

	if err = addAcceptOutgoingPacketRule(conn, n.nft4.Filter, forwardChain, tunname); err != nil {
		return fmt.Errorf("add accept outgoing packet rule v4: %w", err)
	}

	if err = conn.Flush(); err != nil {
		return fmt.Errorf("flush base v4: %w", err)
	}

	return nil
}

// addBase6 adds some basic IPv6 processing rules.
func (n *nftablesRunner) addBase6(tunname string) error {
	conn := n.conn

	inputChain, err := getChainFromTable(conn, n.nft6.Filter, chainNameInput)
	if err != nil {
		return fmt.Errorf("get input chain v4: %v", err)
	}
	if err = addAcceptIncomingPacketRule(conn, n.nft6.Filter, inputChain, tunname); err != nil {
		return fmt.Errorf("add accept incoming packet rule v6: %w", err)
	}

	forwardChain, err := getChainFromTable(conn, n.nft6.Filter, chainNameForward)
	if err != nil {
		return fmt.Errorf("get forward chain v6: %w", err)
	}

	if err = addSetSubnetRouteMarkRule(conn, n.nft6.Filter, forwardChain, tunname); err != nil {
		return fmt.Errorf("add set subnet route mark rule v6: %w", err)
	}

	if err = addMatchSubnetRouteMarkRule(conn, n.nft6.Filter, forwardChain, Accept); err != nil {
		return fmt.Errorf("add match subnet route mark rule v6: %w", err)
	}

	if err = addAcceptOutgoingPacketRule(conn, n.nft6.Filter, forwardChain, tunname); err != nil {
		return fmt.Errorf("add accept outgoing packet rule v6: %w", err)
	}

	if err = conn.Flush(); err != nil {
		return fmt.Errorf("flush base v6: %w", err)
	}

	return nil
}

// DelBase empties, but does not remove, custom Tailscale chains from
// netfilter via iptables.
func (n *nftablesRunner) DelBase() error {
	conn := n.conn

	for _, table := range n.getTables() {
		inputChain, err := getChainFromTable(conn, table.Filter, chainNameInput)
		if err != nil {
			return fmt.Errorf("get input chain: %v", err)
		}
		conn.FlushChain(inputChain)
		forwardChain, err := getChainFromTable(conn, table.Filter, chainNameForward)
		if err != nil {
			return fmt.Errorf("get forward chain: %v", err)
		}
		conn.FlushChain(forwardChain)
	}

	for _, table := range n.getNATTables() {
		postrouteChain, err := getChainFromTable(conn, table.Nat, chainNamePostrouting)
		if err != nil {
			return fmt.Errorf("get postrouting chain v4: %v", err)
		}
		conn.FlushChain(postrouteChain)
	}

	return conn.Flush()
}

// createMatchSubnetRouteMarkRule creates a rule that matches packets
// with the subnet route mark and takes the specified action.
func createMatchSubnetRouteMarkRule(table *nftables.Table, chain *nftables.Chain, action MatchDecision) (*nftables.Rule, error) {
	hexTSFwmarkMask := getTailscaleFwmarkMask()
	hexTSSubnetRouteMark := getTailscaleSubnetRouteMark()

	var endAction expr.Any
	endAction = &expr.Verdict{Kind: expr.VerdictAccept}
	if action == Masq {
		endAction = &expr.Masq{}
	}

	exprs := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           hexTSFwmarkMask,
			Xor:            []byte{0x00, 0x00, 0x00, 0x00},
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     hexTSSubnetRouteMark,
		},
		&expr.Counter{},
		endAction,
	}

	rule := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: exprs,
	}
	return rule, nil
}

// addMatchSubnetRouteMarkRule adds a rule that matches packets with
// the subnet route mark and takes the specified action.
func addMatchSubnetRouteMarkRule(conn *nftables.Conn, table *nftables.Table, chain *nftables.Chain, action MatchDecision) error {
	rule, err := createMatchSubnetRouteMarkRule(table, chain, action)
	if err != nil {
		return fmt.Errorf("create match subnet route mark rule: %w", err)
	}
	_ = conn.AddRule(rule)

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("flush add rule: %w", err)
	}

	return nil
}

// AddSNATRule adds a netfilter rule to SNAT traffic destined for
// local subnets.
func (n *nftablesRunner) AddSNATRule() error {
	conn := n.conn

	for _, table := range n.getNATTables() {
		chain, err := getChainFromTable(conn, table.Nat, chainNamePostrouting)
		if err != nil {
			return fmt.Errorf("get postrouting chain v4: %w", err)
		}

		if err = addMatchSubnetRouteMarkRule(conn, table.Nat, chain, Masq); err != nil {
			return fmt.Errorf("add match subnet route mark rule v4: %w", err)
		}
	}

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("flush add SNAT rule: %w", err)
	}

	return nil
}

// DelSNATRule removes the netfilter rule to SNAT traffic destined for
// local subnets. An error is returned if the rule does not exist.
func (n *nftablesRunner) DelSNATRule() error {
	conn := n.conn

	hexTSFwmarkMask := getTailscaleFwmarkMask()
	hexTSSubnetRouteMark := getTailscaleSubnetRouteMark()

	exprs := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           hexTSFwmarkMask,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     hexTSSubnetRouteMark,
		},
		&expr.Counter{},
		&expr.Masq{},
	}

	for _, table := range n.getNATTables() {
		chain, err := getChainFromTable(conn, table.Nat, chainNamePostrouting)
		if err != nil {
			return fmt.Errorf("get postrouting chain v4: %w", err)
		}

		rule := &nftables.Rule{
			Table: table.Nat,
			Chain: chain,
			Exprs: exprs,
		}

		SNATRule, err := findRule(conn, rule)
		if err != nil {
			return fmt.Errorf("find SNAT rule v4: %w", err)
		}

		if SNATRule != nil {
			_ = conn.DelRule(SNATRule)
		}
	}

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("flush del SNAT rule: %w", err)
	}

	return nil
}

// cleanupChain removes a jump rule from hookChainName to tsChainName, and then
// the entire chain tsChainName. Errors are logged, but attempts to remove both
// the jump rule and chain continue even if one errors.
func cleanupChain(logf logger.Logf, conn *nftables.Conn, table *nftables.Table, hookChainName, tsChainName string) {
	// remove the jump first, before removing the jump destination.
	defaultChain, err := getChainFromTable(conn, table, hookChainName)
	if err != nil && !errors.Is(err, errorChainNotFound{table.Name, hookChainName}) {
		logf("cleanup: did not find default chain: %s", err)
	}
	if !errors.Is(err, errorChainNotFound{table.Name, hookChainName}) {
		// delete hook in convention chain
		_ = delHookRule(conn, table, defaultChain, tsChainName)
	}

	tsChain, err := getChainFromTable(conn, table, tsChainName)
	if err != nil && !errors.Is(err, errorChainNotFound{table.Name, tsChainName}) {
		logf("cleanup: did not find ts-chain: %s", err)
	}

	if tsChain != nil {
		// flush and delete ts-chain
		conn.FlushChain(tsChain)
		conn.DelChain(tsChain)
		err = conn.Flush()
		logf("cleanup: delete and flush chain %s: %s", tsChainName, err)
	}
}

// NfTablesCleanUp removes all Tailscale added nftables rules.
// Any errors that occur are logged to the provided logf.
func NfTablesCleanUp(logf logger.Logf) {
	conn, err := nftables.New()
	if err != nil {
		logf("cleanup: nftables connection: %s", err)
	}

	tables, err := conn.ListTables() // both v4 and v6
	if err != nil {
		logf("cleanup: list tables: %s", err)
	}

	for _, table := range tables {
		// These table names were used briefly in 1.48.0.
		if table.Name == "ts-filter" || table.Name == "ts-nat" {
			conn.DelTable(table)
			if err := conn.Flush(); err != nil {
				logf("cleanup: flush delete table %s: %s", table.Name, err)
			}
		}

		if table.Name == "filter" {
			cleanupChain(logf, conn, table, "INPUT", chainNameInput)
			cleanupChain(logf, conn, table, "FORWARD", chainNameForward)
		}
		if table.Name == "nat" {
			cleanupChain(logf, conn, table, "POSTROUTING", chainNamePostrouting)
		}
	}
}
