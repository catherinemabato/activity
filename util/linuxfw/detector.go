// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package linuxfw

import (
	"tailscale.com/envknob"
	"tailscale.com/hostinfo"
	"tailscale.com/types/logger"
	"tailscale.com/version/distro"
)

func detectFirewallMode(logf logger.Logf) FirewallMode {
	if distro.Get() == distro.Gokrazy {
		// Reduce startup logging on gokrazy. There's no way to do iptables on
		// gokrazy anyway.
		logf("GoKrazy should use nftables.")
		hostinfo.SetFirewallMode("nft-gokrazy")
		return FirewallModeNfTables
	}

	envMode := envknob.String("TS_DEBUG_FIREWALL_MODE")
	// We now use iptables as default and have "auto" and "nftables" as
	// options for people to test further.
	switch envMode {
	case "auto":
		return pickFirewallModeFromInstalledRules(logf, linuxFWDetector{})
	case "nftables":
		logf("envknob TS_DEBUG_FIREWALL_MODE=nftables set")
		hostinfo.SetFirewallMode("nft-forced")
		return FirewallModeNfTables
	case "iptables":
		logf("envknob TS_DEBUG_FIREWALL_MODE=iptables set")
		hostinfo.SetFirewallMode("ipt-forced")
	default:
		logf("default choosing iptables")
		hostinfo.SetFirewallMode("ipt-default")
	}
	return FirewallModeIPTables
}

// tableDetector abstracts helpers to detect the firewall mode.
// It is implemented for testing purposes.
type tableDetector interface {
	iptDetect() (int, error)
	nftDetect() (int, error)
}

type linuxFWDetector struct{}

// iptDetect returns the number of iptables rules in the current namespace.
func (l linuxFWDetector) iptDetect() (int, error) {
	return detectIptables()
}

// nftDetect returns the number of nftables rules in the current namespace.
func (l linuxFWDetector) nftDetect() (int, error) {
	return detectNetfilter()
}

// pickFirewallModeFromInstalledRules returns the firewall mode to use based on
// the environment and the system's capabilities.
func pickFirewallModeFromInstalledRules(logf logger.Logf, det tableDetector) FirewallMode {
	if distro.Get() == distro.Gokrazy {
		// Reduce startup logging on gokrazy. There's no way to do iptables on
		// gokrazy anyway.
		return FirewallModeNfTables
	}
	iptAva, nftAva := true, true
	iptRuleCount, err := det.iptDetect()
	if err != nil {
		logf("detect iptables rule: %v", err)
		iptAva = false
	}
	nftRuleCount, err := det.nftDetect()
	if err != nil {
		logf("detect nftables rule: %v", err)
		nftAva = false
	}
	logf("nftables rule count: %d, iptables rule count: %d", nftRuleCount, iptRuleCount)
	switch {
	case nftRuleCount > 0 && iptRuleCount == 0:
		logf("nftables is currently in use")
		hostinfo.SetFirewallMode("nft-inuse")
		return FirewallModeNfTables
	case iptRuleCount > 0 && nftRuleCount == 0:
		logf("iptables is currently in use")
		hostinfo.SetFirewallMode("ipt-inuse")
		return FirewallModeIPTables
	case nftAva:
		// if both iptables and nftables are available but
		// neither/both are currently used, use nftables.
		logf("nftables is available")
		hostinfo.SetFirewallMode("nft")
		return FirewallModeNfTables
	case iptAva:
		logf("iptables is available")
		hostinfo.SetFirewallMode("ipt")
		return FirewallModeIPTables
	default:
		// if neither iptables nor nftables are available, use iptablesRunner as a dummy
		// runner which exists but won't do anything. Creating iptablesRunner errors only
		// if the iptables command is missing or doesn’t support "--version", as long as it
		// can determine a version then it’ll carry on.
		hostinfo.SetFirewallMode("ipt-fb")
		return FirewallModeIPTables
	}
}
