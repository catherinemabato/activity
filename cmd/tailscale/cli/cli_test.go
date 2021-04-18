// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"strings"
	"testing"

	"inet.af/netaddr"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/logger"
	"tailscale.com/types/preftype"
)

// Test that checkForAccidentalSettingReverts's updateMaskedPrefsFromUpFlag can handle
// all flags. This will panic if a new flag creeps in that's unhandled.
func TestUpdateMaskedPrefsFromUpFlag(t *testing.T) {
	mp := new(ipn.MaskedPrefs)
	upFlagSet.VisitAll(func(f *flag.Flag) {
		updateMaskedPrefsFromUpFlag(mp, f.Name)
	})
}

func TestCheckForAccidentalSettingReverts(t *testing.T) {
	f := func(flags ...string) map[string]bool {
		m := make(map[string]bool)
		for _, f := range flags {
			m[f] = true
		}
		return m
	}
	tests := []struct {
		name     string
		flagSet  map[string]bool
		curPrefs *ipn.Prefs
		mp       *ipn.MaskedPrefs
		want     string
	}{
		{
			name:    "bare_up_means_up",
			flagSet: f(),
			curPrefs: &ipn.Prefs{
				ControlURL:  ipn.DefaultControlURL,
				WantRunning: false,
				Hostname:    "foo",
			},
			mp: &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					WantRunning: true,
				},
				WantRunningSet: true,
			},
			want: "",
		},
		{
			name:    "losing_hostname",
			flagSet: f("accept-dns"),
			curPrefs: &ipn.Prefs{
				ControlURL:  ipn.DefaultControlURL,
				WantRunning: false,
				Hostname:    "foo",
				CorpDNS:     true,
			},
			mp: &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					ControlURL:  ipn.DefaultControlURL,
					WantRunning: true,
					CorpDNS:     true,
				},
				ControlURLSet:  true,
				WantRunningSet: true,
				CorpDNSSet:     true,
			},
			want: `'tailscale up' without --reset requires all preferences with changing values to be explicitly mentioned; --hostname is not specified but its default value of "" differs from current value "foo"`,
		},
		{
			name:    "hostname_changing_explicitly",
			flagSet: f("hostname"),
			curPrefs: &ipn.Prefs{
				ControlURL:  ipn.DefaultControlURL,
				WantRunning: false,
				Hostname:    "foo",
			},
			mp: &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					ControlURL:  ipn.DefaultControlURL,
					WantRunning: true,
					Hostname:    "bar",
				},
				ControlURLSet:  true,
				WantRunningSet: true,
				HostnameSet:    true,
			},
			want: "",
		},
		{
			name:    "hostname_changing_empty_explicitly",
			flagSet: f("hostname"),
			curPrefs: &ipn.Prefs{
				ControlURL:  ipn.DefaultControlURL,
				WantRunning: false,
				Hostname:    "foo",
			},
			mp: &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					ControlURL:  ipn.DefaultControlURL,
					WantRunning: true,
					Hostname:    "",
				},
				ControlURLSet:  true,
				WantRunningSet: true,
				HostnameSet:    true,
			},
			want: "",
		},
		{
			name:    "empty_slice_equals_nil_slice",
			flagSet: f("hostname"),
			curPrefs: &ipn.Prefs{
				ControlURL:      ipn.DefaultControlURL,
				AdvertiseRoutes: []netaddr.IPPrefix{},
			},
			mp: &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					ControlURL:      ipn.DefaultControlURL,
					AdvertiseRoutes: nil,
				},
				ControlURLSet: true,
			},
			want: "",
		},
		{
			// Issue 1725: "tailscale up --authkey=..." (or other non-empty flags) works from
			// a fresh server's initial prefs.
			name:     "up_with_default_prefs",
			flagSet:  f("authkey"),
			curPrefs: ipn.NewPrefs(),
			mp: &ipn.MaskedPrefs{
				Prefs:          *defaultPrefsFromUpArgs(t),
				WantRunningSet: true,
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got string
			if err := checkForAccidentalSettingReverts(tt.flagSet, tt.curPrefs, tt.mp); err != nil {
				got = err.Error()
			}
			if got != tt.want {
				t.Errorf("unexpected result\n got: %s\nwant: %s\n", got, tt.want)
			}
		})
	}
}

func defaultPrefsFromUpArgs(t testing.TB) *ipn.Prefs {
	upFlagSet.Parse(nil) // populates upArgs
	if upFlagSet.Lookup("netfilter-mode") == nil && upArgs.netfilterMode == "" {
		// This flag is not compiled on on-Linux platforms,
		// but prefsFromUpArgs requires it be populated.
		upArgs.netfilterMode = defaultNetfilterMode()
	}
	prefs, err := prefsFromUpArgs(upArgs, logger.Discard, new(ipnstate.Status), "linux")
	if err != nil {
		t.Fatalf("defaultPrefsFromUpArgs: %v", err)
	}
	prefs.WantRunning = true
	return prefs
}

func TestPrefsFromUpArgs(t *testing.T) {
	tests := []struct {
		name     string
		args     upArgsT
		goos     string           // runtime.GOOS; empty means linux
		st       *ipnstate.Status // or nil
		want     *ipn.Prefs
		wantErr  string
		wantWarn string
	}{
		{
			name: "zero",
			goos: "windows",
			args: upArgsT{},
			want: &ipn.Prefs{
				WantRunning:   true,
				NoSNAT:        true,
				NetfilterMode: preftype.NetfilterOn, // silly, but default from ipn.NewPref currently
			},
		},
		{
			name: "error_advertise_route_invalid_ip",
			args: upArgsT{
				advertiseRoutes: "foo",
			},
			wantErr: `"foo" is not a valid IP address or CIDR prefix`,
		},
		{
			name: "error_advertise_route_unmasked_bits",
			args: upArgsT{
				advertiseRoutes: "1.2.3.4/16",
			},
			wantErr: `1.2.3.4/16 has non-address bits set; expected 1.2.0.0/16`,
		},
		{
			name: "error_exit_node_bad_ip",
			args: upArgsT{
				exitNodeIP: "foo",
			},
			wantErr: `invalid IP address "foo" for --exit-node: unable to parse IP`,
		},
		{
			name: "error_exit_node_allow_lan_without_exit_node",
			args: upArgsT{
				exitNodeAllowLANAccess: true,
			},
			wantErr: `--exit-node-allow-lan-access can only be used with --exit-node`,
		},
		{
			name: "error_tag_prefix",
			args: upArgsT{
				advertiseTags: "foo",
			},
			wantErr: `tag: "foo": tags must start with 'tag:'`,
		},
		{
			name: "error_long_hostname",
			args: upArgsT{
				hostname: strings.Repeat("a", 300),
			},
			wantErr: `hostname too long: 300 bytes (max 256)`,
		},
		{
			name: "error_linux_netfilter_empty",
			args: upArgsT{
				netfilterMode: "",
			},
			wantErr: `invalid value --netfilter-mode=""`,
		},
		{
			name: "error_linux_netfilter_bogus",
			args: upArgsT{
				netfilterMode: "bogus",
			},
			wantErr: `invalid value --netfilter-mode="bogus"`,
		},
		{
			name: "error_exit_node_ip_is_self_ip",
			args: upArgsT{
				exitNodeIP: "100.105.106.107",
			},
			st: &ipnstate.Status{
				TailscaleIPs: []netaddr.IP{netaddr.MustParseIP("100.105.106.107")},
			},
			wantErr: `cannot use 100.105.106.107 as the exit node as it is a local IP address to this machine, did you mean --advertise-exit-node?`,
		},
		{
			name: "warn_linux_netfilter_nodivert",
			goos: "linux",
			args: upArgsT{
				netfilterMode: "nodivert",
			},
			wantWarn: "netfilter=nodivert; add iptables calls to ts-* chains manually.",
			want: &ipn.Prefs{
				WantRunning:   true,
				NetfilterMode: preftype.NetfilterNoDivert,
				NoSNAT:        true,
			},
		},
		{
			name: "warn_linux_netfilter_off",
			goos: "linux",
			args: upArgsT{
				netfilterMode: "off",
			},
			wantWarn: "netfilter=off; configure iptables yourself.",
			want: &ipn.Prefs{
				WantRunning:   true,
				NetfilterMode: preftype.NetfilterOff,
				NoSNAT:        true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var warnBuf bytes.Buffer
			warnf := func(format string, a ...interface{}) {
				fmt.Fprintf(&warnBuf, format, a...)
			}
			goos := tt.goos
			if goos == "" {
				goos = "linux"
			}
			st := tt.st
			if st == nil {
				st = new(ipnstate.Status)
			}
			got, err := prefsFromUpArgs(tt.args, warnf, st, goos)
			gotErr := fmt.Sprint(err)
			if tt.wantErr != "" {
				if tt.wantErr != gotErr {
					t.Errorf("wrong error.\n got error: %v\nwant error: %v\n", gotErr, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.want == nil {
				t.Fatal("tt.want is nil")
			}
			if !got.Equals(tt.want) {
				jgot, _ := json.MarshalIndent(got, "", "\t")
				jwant, _ := json.MarshalIndent(tt.want, "", "\t")
				if bytes.Equal(jgot, jwant) {
					t.Logf("prefs differ only in non-JSON-visible ways (nil/non-nil zero-length arrays)")
				}
				t.Errorf("wrong prefs\n got: %s\nwant: %s\n\ngot: %s\nwant: %s\n",
					got.Pretty(), tt.want.Pretty(),
					jgot, jwant,
				)

			}
		})
	}

}
