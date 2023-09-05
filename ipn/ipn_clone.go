// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Code generated by tailscale.com/cmd/cloner; DO NOT EDIT.

package ipn

import (
	"maps"
	"net/netip"

	"tailscale.com/tailcfg"
	"tailscale.com/types/persist"
	"tailscale.com/types/preftype"
)

// Clone makes a deep copy of Prefs.
// The result aliases no memory with the original.
func (src *Prefs) Clone() *Prefs {
	if src == nil {
		return nil
	}
	dst := new(Prefs)
	*dst = *src
	dst.AdvertiseTags = append(src.AdvertiseTags[:0:0], src.AdvertiseTags...)
	dst.AdvertiseRoutes = append(src.AdvertiseRoutes[:0:0], src.AdvertiseRoutes...)
	dst.Persist = src.Persist.Clone()
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _PrefsCloneNeedsRegeneration = Prefs(struct {
	ControlURL             string
	RouteAll               bool
	AllowSingleHosts       bool
	ExitNodeID             tailcfg.StableNodeID
	ExitNodeIP             netip.Addr
	ExitNodeAllowLANAccess bool
	CorpDNS                bool
	RunSSH                 bool
	WantRunning            bool
	LoggedOut              bool
	ShieldsUp              bool
	AdvertiseTags          []string
	Hostname               string
	NotepadURLs            bool
	ForceDaemon            bool
	Egg                    bool
	AdvertiseRoutes        []netip.Prefix
	NoSNAT                 bool
	NetfilterMode          preftype.NetfilterMode
	OperatorUser           string
	ProfileName            string
	AutoUpdate             AutoUpdatePrefs
	Persist                *persist.Persist
}{})

// Clone makes a deep copy of ServeConfig.
// The result aliases no memory with the original.
func (src *ServeConfig) Clone() *ServeConfig {
	if src == nil {
		return nil
	}
	dst := new(ServeConfig)
	*dst = *src
	if dst.TCP != nil {
		dst.TCP = map[uint16]*TCPPortHandler{}
		for k, v := range src.TCP {
			dst.TCP[k] = v.Clone()
		}
	}
	if dst.Web != nil {
		dst.Web = map[HostPort]*WebServerConfig{}
		for k, v := range src.Web {
			dst.Web[k] = v.Clone()
		}
	}
	dst.AllowFunnel = maps.Clone(src.AllowFunnel)
	if dst.Foreground != nil {
		dst.Foreground = map[string]*ServeConfig{}
		for k, v := range src.Foreground {
			dst.Foreground[k] = v.Clone()
		}
	}
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _ServeConfigCloneNeedsRegeneration = ServeConfig(struct {
	TCP         map[uint16]*TCPPortHandler
	Web         map[HostPort]*WebServerConfig
	AllowFunnel map[HostPort]bool
	Foreground  map[string]*ServeConfig
}{})

// Clone makes a deep copy of TCPPortHandler.
// The result aliases no memory with the original.
func (src *TCPPortHandler) Clone() *TCPPortHandler {
	if src == nil {
		return nil
	}
	dst := new(TCPPortHandler)
	*dst = *src
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _TCPPortHandlerCloneNeedsRegeneration = TCPPortHandler(struct {
	HTTPS        bool
	HTTP         bool
	TCPForward   string
	TerminateTLS string
}{})

// Clone makes a deep copy of HTTPHandler.
// The result aliases no memory with the original.
func (src *HTTPHandler) Clone() *HTTPHandler {
	if src == nil {
		return nil
	}
	dst := new(HTTPHandler)
	*dst = *src
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _HTTPHandlerCloneNeedsRegeneration = HTTPHandler(struct {
	Path  string
	Proxy string
	Text  string
}{})

// Clone makes a deep copy of WebServerConfig.
// The result aliases no memory with the original.
func (src *WebServerConfig) Clone() *WebServerConfig {
	if src == nil {
		return nil
	}
	dst := new(WebServerConfig)
	*dst = *src
	if dst.Handlers != nil {
		dst.Handlers = map[string]*HTTPHandler{}
		for k, v := range src.Handlers {
			dst.Handlers[k] = v.Clone()
		}
	}
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _WebServerConfigCloneNeedsRegeneration = WebServerConfig(struct {
	Handlers map[string]*HTTPHandler
}{})
