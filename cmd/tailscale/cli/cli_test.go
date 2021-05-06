// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"reflect"
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
		curUser  string // os.Getenv("USER") on the client side
		goos     string // empty means "linux"
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
			want: accidentalUpPrefix + " --accept-dns --hostname=foo",
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
				Prefs:          *defaultPrefsFromUpArgs(t, "linux"),
				WantRunningSet: true,
			},
			want: "",
		},
		{
			name:    "implicit_operator_change",
			flagSet: f("hostname"),
			curPrefs: &ipn.Prefs{
				ControlURL:   ipn.DefaultControlURL,
				OperatorUser: "alice",
			},
			curUser: "eve",
			mp: &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					ControlURL: ipn.DefaultControlURL,
				},
				ControlURLSet: true,
			},
			want: accidentalUpPrefix + " --hostname= --operator=alice",
		},
		{
			name:    "implicit_operator_matches_shell_user",
			flagSet: f("hostname"),
			curPrefs: &ipn.Prefs{
				ControlURL:   ipn.DefaultControlURL,
				OperatorUser: "alice",
			},
			curUser: "alice",
			mp: &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					ControlURL: ipn.DefaultControlURL,
				},
				ControlURLSet: true,
			},
			want: "",
		},
		{
			name:    "error_advertised_routes_exit_node_removed",
			flagSet: f("advertise-routes"),
			curPrefs: &ipn.Prefs{
				ControlURL: ipn.DefaultControlURL,
				AdvertiseRoutes: []netaddr.IPPrefix{
					netaddr.MustParseIPPrefix("10.0.42.0/24"),
					netaddr.MustParseIPPrefix("0.0.0.0/0"),
					netaddr.MustParseIPPrefix("::/0"),
				},
			},
			mp: &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					ControlURL: ipn.DefaultControlURL,
					AdvertiseRoutes: []netaddr.IPPrefix{
						netaddr.MustParseIPPrefix("10.0.42.0/24"),
					},
				},
				AdvertiseRoutesSet: true,
			},
			want: accidentalUpPrefix + " --advertise-routes=10.0.42.0/24 --advertise-exit-node",
		},
		{
			name:    "advertised_routes_exit_node_removed",
			flagSet: f("advertise-routes", "advertise-exit-node"),
			curPrefs: &ipn.Prefs{
				ControlURL: ipn.DefaultControlURL,
				AdvertiseRoutes: []netaddr.IPPrefix{
					netaddr.MustParseIPPrefix("10.0.42.0/24"),
					netaddr.MustParseIPPrefix("0.0.0.0/0"),
					netaddr.MustParseIPPrefix("::/0"),
				},
			},
			mp: &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					ControlURL: ipn.DefaultControlURL,
					AdvertiseRoutes: []netaddr.IPPrefix{
						netaddr.MustParseIPPrefix("10.0.42.0/24"),
					},
				},
				AdvertiseRoutesSet: true,
			},
			want: "",
		},
		{
			name:    "advertised_routes_includes_the_0_routes", // but no --advertise-exit-node
			flagSet: f("advertise-routes"),
			curPrefs: &ipn.Prefs{
				ControlURL: ipn.DefaultControlURL,
				AdvertiseRoutes: []netaddr.IPPrefix{
					netaddr.MustParseIPPrefix("10.0.42.0/24"),
					netaddr.MustParseIPPrefix("0.0.0.0/0"),
					netaddr.MustParseIPPrefix("::/0"),
				},
			},
			mp: &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					ControlURL: ipn.DefaultControlURL,
					AdvertiseRoutes: []netaddr.IPPrefix{
						netaddr.MustParseIPPrefix("11.1.43.0/24"),
						netaddr.MustParseIPPrefix("0.0.0.0/0"),
						netaddr.MustParseIPPrefix("::/0"),
					},
				},
				AdvertiseRoutesSet: true,
			},
			want: "",
		},
		{
			name:    "advertised_routes_includes_only_one_0_route", // and no --advertise-exit-node
			flagSet: f("advertise-routes"),
			curPrefs: &ipn.Prefs{
				ControlURL: ipn.DefaultControlURL,
				AdvertiseRoutes: []netaddr.IPPrefix{
					netaddr.MustParseIPPrefix("10.0.42.0/24"),
					netaddr.MustParseIPPrefix("0.0.0.0/0"),
					netaddr.MustParseIPPrefix("::/0"),
				},
			},
			mp: &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					ControlURL: ipn.DefaultControlURL,
					AdvertiseRoutes: []netaddr.IPPrefix{
						netaddr.MustParseIPPrefix("11.1.43.0/24"),
						netaddr.MustParseIPPrefix("0.0.0.0/0"),
					},
				},
				AdvertiseRoutesSet: true,
			},
			want: accidentalUpPrefix + " --advertise-routes=11.1.43.0/24,0.0.0.0/0 --advertise-exit-node",
		},
		{
			name:    "advertise_exit_node", // Issue 1859
			flagSet: f("advertise-exit-node"),
			curPrefs: &ipn.Prefs{
				ControlURL: ipn.DefaultControlURL,
			},
			mp: &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					ControlURL: ipn.DefaultControlURL,
					AdvertiseRoutes: []netaddr.IPPrefix{
						netaddr.MustParseIPPrefix("0.0.0.0/0"),
						netaddr.MustParseIPPrefix("::/0"),
					},
				},
				// Note: without setting "AdvertiseRoutesSet", as
				// updateMaskedPrefsFromUpFlag doesn't set that.
			},
			want: "",
		},
		{
			name:    "advertise_exit_node_over_existing_routes",
			flagSet: f("advertise-exit-node"),
			curPrefs: &ipn.Prefs{
				ControlURL: ipn.DefaultControlURL,
				AdvertiseRoutes: []netaddr.IPPrefix{
					netaddr.MustParseIPPrefix("1.2.0.0/16"),
				},
			},
			mp: &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					ControlURL: ipn.DefaultControlURL,
					AdvertiseRoutes: []netaddr.IPPrefix{
						netaddr.MustParseIPPrefix("0.0.0.0/0"),
						netaddr.MustParseIPPrefix("::/0"),
					},
				},
				// Note: without setting "AdvertiseRoutesSet", as
				// updateMaskedPrefsFromUpFlag doesn't set that.
			},
			want: accidentalUpPrefix + " --advertise-exit-node --advertise-routes=1.2.0.0/16",
		},
		{
			name:    "advertise_exit_node_over_existing_routes_and_exit_node",
			flagSet: f("advertise-exit-node"),
			curPrefs: &ipn.Prefs{
				ControlURL: ipn.DefaultControlURL,
				AdvertiseRoutes: []netaddr.IPPrefix{
					netaddr.MustParseIPPrefix("0.0.0.0/0"),
					netaddr.MustParseIPPrefix("::/0"),
					netaddr.MustParseIPPrefix("1.2.0.0/16"),
				},
			},
			mp: &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					ControlURL: ipn.DefaultControlURL,
					AdvertiseRoutes: []netaddr.IPPrefix{
						netaddr.MustParseIPPrefix("0.0.0.0/0"),
						netaddr.MustParseIPPrefix("::/0"),
					},
				},
				// Note: without setting "AdvertiseRoutesSet", as
				// updateMaskedPrefsFromUpFlag doesn't set that.
			},
			want: accidentalUpPrefix + " --advertise-exit-node --advertise-routes=1.2.0.0/16",
		},
		{
			name:    "exit_node_clearing", // Issue 1777
			flagSet: f("exit-node"),
			curPrefs: &ipn.Prefs{
				ControlURL: ipn.DefaultControlURL,
				ExitNodeID: "fooID",
			},
			mp: &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					ControlURL: ipn.DefaultControlURL,
					ExitNodeIP: netaddr.IP{},
				},
				ExitNodeIPSet: true,
			},
			want: "",
		},
		{
			name:    "remove_all_implicit",
			flagSet: f("force-reauth"),
			curPrefs: &ipn.Prefs{
				WantRunning:      true,
				ControlURL:       ipn.DefaultControlURL,
				RouteAll:         true,
				AllowSingleHosts: false,
				ExitNodeIP:       netaddr.MustParseIP("100.64.5.6"),
				CorpDNS:          true,
				ShieldsUp:        true,
				AdvertiseTags:    []string{"tag:foo", "tag:bar"},
				Hostname:         "myhostname",
				ForceDaemon:      true,
				AdvertiseRoutes: []netaddr.IPPrefix{
					netaddr.MustParseIPPrefix("10.0.0.0/16"),
				},
				NetfilterMode: preftype.NetfilterNoDivert,
				OperatorUser:  "alice",
			},
			curUser: "eve",
			mp: &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					ControlURL:  ipn.DefaultControlURL,
					WantRunning: true,
				},
			},
			want: accidentalUpPrefix + " --force-reauth --accept-routes --exit-node=100.64.5.6 --accept-dns --shields-up --advertise-tags=tag:foo,tag:bar --hostname=myhostname --unattended --advertise-routes=10.0.0.0/16 --netfilter-mode=nodivert --operator=alice",
		},
		{
			name:    "remove_all_implicit_except_hostname",
			flagSet: f("hostname"),
			curPrefs: &ipn.Prefs{
				WantRunning:      true,
				ControlURL:       ipn.DefaultControlURL,
				RouteAll:         true,
				AllowSingleHosts: false,
				ExitNodeIP:       netaddr.MustParseIP("100.64.5.6"),
				CorpDNS:          true,
				ShieldsUp:        true,
				AdvertiseTags:    []string{"tag:foo", "tag:bar"},
				Hostname:         "myhostname",
				ForceDaemon:      true,
				AdvertiseRoutes: []netaddr.IPPrefix{
					netaddr.MustParseIPPrefix("10.0.0.0/16"),
				},
				NetfilterMode: preftype.NetfilterNoDivert,
				OperatorUser:  "alice",
			},
			curUser: "eve",
			mp: &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					ControlURL:  ipn.DefaultControlURL,
					WantRunning: true,
					Hostname:    "newhostname",
				},
				HostnameSet: true,
			},
			want: accidentalUpPrefix + " --hostname=newhostname --accept-routes --exit-node=100.64.5.6 --accept-dns --shields-up --advertise-tags=tag:foo,tag:bar --unattended --advertise-routes=10.0.0.0/16 --netfilter-mode=nodivert --operator=alice",
		},
		{
			name:    "loggedout_is_implicit",
			flagSet: f("advertise-exit-node"),
			curPrefs: &ipn.Prefs{
				ControlURL: ipn.DefaultControlURL,
				LoggedOut:  true,
			},
			mp: &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					ControlURL: ipn.DefaultControlURL,
					AdvertiseRoutes: []netaddr.IPPrefix{
						netaddr.MustParseIPPrefix("0.0.0.0/0"),
					},
				},
				AdvertiseRoutesSet: true,
			},
			// not an error. LoggedOut is implicit.
			want: "",
		},
		{
			// Test that a pre-1.8 version of Tailscale with bogus NoSNAT pref
			// values is able to enable exit nodes without warnings.
			name:    "make_windows_exit_node",
			flagSet: f("advertise-exit-node"),
			curPrefs: &ipn.Prefs{
				ControlURL: ipn.DefaultControlURL,
				NoSNAT:     true, // assume this no-op accidental pre-1.8 value
			},
			goos: "windows",
			mp: &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					ControlURL: ipn.DefaultControlURL,
					AdvertiseRoutes: []netaddr.IPPrefix{
						netaddr.MustParseIPPrefix("192.168.0.0/16"),
					},
				},
				AdvertiseRoutesSet: true,
			},
			want: "", // not an error
		},
		{
			name:    "ignore_netfilter_change_non_linux",
			flagSet: f("accept-dns"),
			curPrefs: &ipn.Prefs{
				ControlURL:    ipn.DefaultControlURL,
				NetfilterMode: preftype.NetfilterNoDivert, // we never had this bug, but pretend it got set non-zero on Windows somehow
			},
			goos: "windows",
			mp: &ipn.MaskedPrefs{
				Prefs: ipn.Prefs{
					ControlURL: ipn.DefaultControlURL,
					CorpDNS:    false,
				},
				CorpDNSSet: true,
			},
			want: "", // not an error
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			goos := "linux"
			if tt.goos != "" {
				goos = tt.goos
			}
			var got string
			if err := checkForAccidentalSettingReverts(tt.flagSet, tt.curPrefs, tt.mp, goos, tt.curUser); err != nil {
				got = err.Error()
			}
			if strings.TrimSpace(got) != tt.want {
				t.Errorf("unexpected result\n got: %s\nwant: %s\n", got, tt.want)
			}
		})
	}
}

func defaultPrefsFromUpArgs(t testing.TB, goos string) *ipn.Prefs {
	upArgs := upArgsFromOSArgs(goos)
	prefs, err := prefsFromUpArgs(upArgs, logger.Discard, new(ipnstate.Status), "linux")
	if err != nil {
		t.Fatalf("defaultPrefsFromUpArgs: %v", err)
	}
	prefs.WantRunning = true
	return prefs
}

func upArgsFromOSArgs(goos string, flagArgs ...string) (args upArgsT) {
	fs := newUpFlagSet(goos, &args)
	fs.Parse(flagArgs) // populates args
	return
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
			name: "default_linux",
			goos: "linux",
			args: upArgsFromOSArgs("linux"),
			want: &ipn.Prefs{
				ControlURL:       ipn.DefaultControlURL,
				WantRunning:      true,
				NoSNAT:           false,
				NetfilterMode:    preftype.NetfilterOn,
				CorpDNS:          true,
				AllowSingleHosts: true,
			},
		},
		{
			name: "default_windows",
			goos: "windows",
			args: upArgsFromOSArgs("windows"),
			want: &ipn.Prefs{
				ControlURL:       ipn.DefaultControlURL,
				WantRunning:      true,
				CorpDNS:          true,
				AllowSingleHosts: true,
				NetfilterMode:    preftype.NetfilterOn,
			},
		},
		{
			name: "advertise_default_route",
			args: upArgsFromOSArgs("linux", "--advertise-exit-node"),
			want: &ipn.Prefs{
				ControlURL:       ipn.DefaultControlURL,
				WantRunning:      true,
				AllowSingleHosts: true,
				CorpDNS:          true,
				AdvertiseRoutes: []netaddr.IPPrefix{
					netaddr.MustParseIPPrefix("0.0.0.0/0"),
					netaddr.MustParseIPPrefix("::/0"),
				},
				NetfilterMode: preftype.NetfilterOn,
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

func TestPrefFlagMapping(t *testing.T) {
	prefType := reflect.TypeOf(ipn.Prefs{})
	for i := 0; i < prefType.NumField(); i++ {
		prefName := prefType.Field(i).Name
		if _, ok := flagForPref[prefName]; ok {
			continue
		}
		switch prefName {
		case "WantRunning", "Persist", "LoggedOut":
			// All explicitly handled (ignored) by checkForAccidentalSettingReverts.
			continue
		case "OSVersion", "DeviceModel":
			// Only used by Android, which doesn't have a CLI mode anyway, so
			// fine to not map.
			continue
		case "NotepadURLs":
			// TODO(bradfitz): https://github.com/tailscale/tailscale/issues/1830
			continue
		}
		t.Errorf("unexpected new ipn.Pref field %q is not handled by up.go (see addPrefFlagMapping and checkForAccidentalSettingReverts)", prefName)
	}
}
