// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Code generated by tailscale.com/cmd/cloner; DO NOT EDIT.

package tailcfg

import (
	"maps"
	"net/netip"
	"time"

	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
	"tailscale.com/types/opt"
	"tailscale.com/types/ptr"
	"tailscale.com/types/structs"
	"tailscale.com/types/tkatype"
)

// Clone makes a deep copy of User.
// The result aliases no memory with the original.
func (src *User) Clone() *User {
	if src == nil {
		return nil
	}
	dst := new(User)
	*dst = *src
	dst.Logins = append(src.Logins[:0:0], src.Logins...)
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _UserCloneNeedsRegeneration = User(struct {
	ID            UserID
	LoginName     string
	DisplayName   string
	ProfilePicURL string
	Logins        []LoginID
	Created       time.Time
}{})

// Clone makes a deep copy of Node.
// The result aliases no memory with the original.
func (src *Node) Clone() *Node {
	if src == nil {
		return nil
	}
	dst := new(Node)
	*dst = *src
	dst.KeySignature = append(src.KeySignature[:0:0], src.KeySignature...)
	dst.Addresses = append(src.Addresses[:0:0], src.Addresses...)
	dst.AllowedIPs = append(src.AllowedIPs[:0:0], src.AllowedIPs...)
	dst.Endpoints = append(src.Endpoints[:0:0], src.Endpoints...)
	dst.Hostinfo = src.Hostinfo
	dst.Tags = append(src.Tags[:0:0], src.Tags...)
	dst.PrimaryRoutes = append(src.PrimaryRoutes[:0:0], src.PrimaryRoutes...)
	if dst.LastSeen != nil {
		dst.LastSeen = ptr.To(*src.LastSeen)
	}
	if dst.Online != nil {
		dst.Online = ptr.To(*src.Online)
	}
	dst.Capabilities = append(src.Capabilities[:0:0], src.Capabilities...)
	if dst.CapMap != nil {
		dst.CapMap = map[NodeCapability][]RawMessage{}
		for k := range src.CapMap {
			dst.CapMap[k] = append([]RawMessage{}, src.CapMap[k]...)
		}
	}
	if dst.SelfNodeV4MasqAddrForThisPeer != nil {
		dst.SelfNodeV4MasqAddrForThisPeer = ptr.To(*src.SelfNodeV4MasqAddrForThisPeer)
	}
	if dst.SelfNodeV6MasqAddrForThisPeer != nil {
		dst.SelfNodeV6MasqAddrForThisPeer = ptr.To(*src.SelfNodeV6MasqAddrForThisPeer)
	}
	if src.ExitNodeDNSResolvers != nil {
		dst.ExitNodeDNSResolvers = make([]*dnstype.Resolver, len(src.ExitNodeDNSResolvers))
		for i := range dst.ExitNodeDNSResolvers {
			dst.ExitNodeDNSResolvers[i] = src.ExitNodeDNSResolvers[i].Clone()
		}
	}
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _NodeCloneNeedsRegeneration = Node(struct {
	ID                            NodeID
	StableID                      StableNodeID
	Name                          string
	User                          UserID
	Sharer                        UserID
	Key                           key.NodePublic
	KeyExpiry                     time.Time
	KeySignature                  tkatype.MarshaledSignature
	Machine                       key.MachinePublic
	DiscoKey                      key.DiscoPublic
	Addresses                     []netip.Prefix
	AllowedIPs                    []netip.Prefix
	Endpoints                     []netip.AddrPort
	DERP                          string
	Hostinfo                      HostinfoView
	Created                       time.Time
	Cap                           CapabilityVersion
	Tags                          []string
	PrimaryRoutes                 []netip.Prefix
	LastSeen                      *time.Time
	Online                        *bool
	MachineAuthorized             bool
	Capabilities                  []NodeCapability
	CapMap                        NodeCapMap
	UnsignedPeerAPIOnly           bool
	ComputedName                  string
	computedHostIfDifferent       string
	ComputedNameWithHost          string
	DataPlaneAuditLogID           string
	Expired                       bool
	SelfNodeV4MasqAddrForThisPeer *netip.Addr
	SelfNodeV6MasqAddrForThisPeer *netip.Addr
	IsWireGuardOnly               bool
	IsJailed                      bool
	ExitNodeDNSResolvers          []*dnstype.Resolver
}{})

// Clone makes a deep copy of Hostinfo.
// The result aliases no memory with the original.
func (src *Hostinfo) Clone() *Hostinfo {
	if src == nil {
		return nil
	}
	dst := new(Hostinfo)
	*dst = *src
	dst.RoutableIPs = append(src.RoutableIPs[:0:0], src.RoutableIPs...)
	dst.RequestTags = append(src.RequestTags[:0:0], src.RequestTags...)
	dst.WoLMACs = append(src.WoLMACs[:0:0], src.WoLMACs...)
	dst.Services = append(src.Services[:0:0], src.Services...)
	dst.NetInfo = src.NetInfo.Clone()
	dst.SSH_HostKeys = append(src.SSH_HostKeys[:0:0], src.SSH_HostKeys...)
	if dst.Location != nil {
		dst.Location = ptr.To(*src.Location)
	}
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _HostinfoCloneNeedsRegeneration = Hostinfo(struct {
	IPNVersion      string
	FrontendLogID   string
	BackendLogID    string
	OS              string
	OSVersion       string
	Container       opt.Bool
	Env             string
	Distro          string
	DistroVersion   string
	DistroCodeName  string
	App             string
	Desktop         opt.Bool
	Package         string
	DeviceModel     string
	PushDeviceToken string
	Hostname        string
	ShieldsUp       bool
	ShareeNode      bool
	NoLogsNoSupport bool
	WireIngress     bool
	AllowsUpdate    bool
	Machine         string
	GoArch          string
	GoArchVar       string
	GoVersion       string
	RoutableIPs     []netip.Prefix
	RequestTags     []string
	WoLMACs         []string
	Services        []Service
	NetInfo         *NetInfo
	SSH_HostKeys    []string
	Cloud           string
	Userspace       opt.Bool
	UserspaceRouter opt.Bool
	AppConnector    opt.Bool
	Location        *Location
}{})

// Clone makes a deep copy of NetInfo.
// The result aliases no memory with the original.
func (src *NetInfo) Clone() *NetInfo {
	if src == nil {
		return nil
	}
	dst := new(NetInfo)
	*dst = *src
	dst.DERPLatency = maps.Clone(src.DERPLatency)
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _NetInfoCloneNeedsRegeneration = NetInfo(struct {
	MappingVariesByDestIP opt.Bool
	HairPinning           opt.Bool
	WorkingIPv6           opt.Bool
	OSHasIPv6             opt.Bool
	WorkingUDP            opt.Bool
	WorkingICMPv4         opt.Bool
	HavePortMap           bool
	UPnP                  opt.Bool
	PMP                   opt.Bool
	PCP                   opt.Bool
	PreferredDERP         int
	LinkType              string
	DERPLatency           map[string]float64
	FirewallMode          string
}{})

// Clone makes a deep copy of Login.
// The result aliases no memory with the original.
func (src *Login) Clone() *Login {
	if src == nil {
		return nil
	}
	dst := new(Login)
	*dst = *src
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _LoginCloneNeedsRegeneration = Login(struct {
	_             structs.Incomparable
	ID            LoginID
	Provider      string
	LoginName     string
	DisplayName   string
	ProfilePicURL string
}{})

// Clone makes a deep copy of DNSConfig.
// The result aliases no memory with the original.
func (src *DNSConfig) Clone() *DNSConfig {
	if src == nil {
		return nil
	}
	dst := new(DNSConfig)
	*dst = *src
	if src.Resolvers != nil {
		dst.Resolvers = make([]*dnstype.Resolver, len(src.Resolvers))
		for i := range dst.Resolvers {
			dst.Resolvers[i] = src.Resolvers[i].Clone()
		}
	}
	if dst.Routes != nil {
		dst.Routes = map[string][]*dnstype.Resolver{}
		for k := range src.Routes {
			dst.Routes[k] = append([]*dnstype.Resolver{}, src.Routes[k]...)
		}
	}
	if src.FallbackResolvers != nil {
		dst.FallbackResolvers = make([]*dnstype.Resolver, len(src.FallbackResolvers))
		for i := range dst.FallbackResolvers {
			dst.FallbackResolvers[i] = src.FallbackResolvers[i].Clone()
		}
	}
	dst.Domains = append(src.Domains[:0:0], src.Domains...)
	dst.Nameservers = append(src.Nameservers[:0:0], src.Nameservers...)
	dst.CertDomains = append(src.CertDomains[:0:0], src.CertDomains...)
	dst.ExtraRecords = append(src.ExtraRecords[:0:0], src.ExtraRecords...)
	dst.ExitNodeFilteredSet = append(src.ExitNodeFilteredSet[:0:0], src.ExitNodeFilteredSet...)
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _DNSConfigCloneNeedsRegeneration = DNSConfig(struct {
	Resolvers           []*dnstype.Resolver
	Routes              map[string][]*dnstype.Resolver
	FallbackResolvers   []*dnstype.Resolver
	Domains             []string
	Proxied             bool
	Nameservers         []netip.Addr
	CertDomains         []string
	ExtraRecords        []DNSRecord
	ExitNodeFilteredSet []string
	TempCorpIssue13969  string
}{})

// Clone makes a deep copy of RegisterResponse.
// The result aliases no memory with the original.
func (src *RegisterResponse) Clone() *RegisterResponse {
	if src == nil {
		return nil
	}
	dst := new(RegisterResponse)
	*dst = *src
	dst.User = *src.User.Clone()
	dst.NodeKeySignature = append(src.NodeKeySignature[:0:0], src.NodeKeySignature...)
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _RegisterResponseCloneNeedsRegeneration = RegisterResponse(struct {
	User              User
	Login             Login
	NodeKeyExpired    bool
	MachineAuthorized bool
	AuthURL           string
	NodeKeySignature  tkatype.MarshaledSignature
	Error             string
}{})

// Clone makes a deep copy of RegisterResponseAuth.
// The result aliases no memory with the original.
func (src *RegisterResponseAuth) Clone() *RegisterResponseAuth {
	if src == nil {
		return nil
	}
	dst := new(RegisterResponseAuth)
	*dst = *src
	if dst.Oauth2Token != nil {
		dst.Oauth2Token = ptr.To(*src.Oauth2Token)
	}
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _RegisterResponseAuthCloneNeedsRegeneration = RegisterResponseAuth(struct {
	_           structs.Incomparable
	Oauth2Token *Oauth2Token
	AuthKey     string
}{})

// Clone makes a deep copy of RegisterRequest.
// The result aliases no memory with the original.
func (src *RegisterRequest) Clone() *RegisterRequest {
	if src == nil {
		return nil
	}
	dst := new(RegisterRequest)
	*dst = *src
	dst.Auth = src.Auth.Clone()
	dst.Hostinfo = src.Hostinfo.Clone()
	dst.NodeKeySignature = append(src.NodeKeySignature[:0:0], src.NodeKeySignature...)
	if dst.Timestamp != nil {
		dst.Timestamp = ptr.To(*src.Timestamp)
	}
	dst.DeviceCert = append(src.DeviceCert[:0:0], src.DeviceCert...)
	dst.Signature = append(src.Signature[:0:0], src.Signature...)
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _RegisterRequestCloneNeedsRegeneration = RegisterRequest(struct {
	_                structs.Incomparable
	Version          CapabilityVersion
	NodeKey          key.NodePublic
	OldNodeKey       key.NodePublic
	NLKey            key.NLPublic
	Auth             *RegisterResponseAuth
	Expiry           time.Time
	Followup         string
	Hostinfo         *Hostinfo
	Ephemeral        bool
	NodeKeySignature tkatype.MarshaledSignature
	SignatureType    SignatureType
	Timestamp        *time.Time
	DeviceCert       []byte
	Signature        []byte
	Tailnet          string
}{})

// Clone makes a deep copy of DERPHomeParams.
// The result aliases no memory with the original.
func (src *DERPHomeParams) Clone() *DERPHomeParams {
	if src == nil {
		return nil
	}
	dst := new(DERPHomeParams)
	*dst = *src
	dst.RegionScore = maps.Clone(src.RegionScore)
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _DERPHomeParamsCloneNeedsRegeneration = DERPHomeParams(struct {
	RegionScore map[int]float64
}{})

// Clone makes a deep copy of DERPRegion.
// The result aliases no memory with the original.
func (src *DERPRegion) Clone() *DERPRegion {
	if src == nil {
		return nil
	}
	dst := new(DERPRegion)
	*dst = *src
	if src.Nodes != nil {
		dst.Nodes = make([]*DERPNode, len(src.Nodes))
		for i := range dst.Nodes {
			dst.Nodes[i] = src.Nodes[i].Clone()
		}
	}
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _DERPRegionCloneNeedsRegeneration = DERPRegion(struct {
	RegionID   int
	RegionCode string
	RegionName string
	Latitude   float64
	Longitude  float64
	Avoid      bool
	Nodes      []*DERPNode
}{})

// Clone makes a deep copy of DERPMap.
// The result aliases no memory with the original.
func (src *DERPMap) Clone() *DERPMap {
	if src == nil {
		return nil
	}
	dst := new(DERPMap)
	*dst = *src
	dst.HomeParams = src.HomeParams.Clone()
	if dst.Regions != nil {
		dst.Regions = map[int]*DERPRegion{}
		for k, v := range src.Regions {
			dst.Regions[k] = v.Clone()
		}
	}
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _DERPMapCloneNeedsRegeneration = DERPMap(struct {
	HomeParams         *DERPHomeParams
	Regions            map[int]*DERPRegion
	OmitDefaultRegions bool
}{})

// Clone makes a deep copy of DERPNode.
// The result aliases no memory with the original.
func (src *DERPNode) Clone() *DERPNode {
	if src == nil {
		return nil
	}
	dst := new(DERPNode)
	*dst = *src
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _DERPNodeCloneNeedsRegeneration = DERPNode(struct {
	Name             string
	RegionID         int
	HostName         string
	CertName         string
	IPv4             string
	IPv6             string
	STUNPort         int
	STUNOnly         bool
	DERPPort         int
	InsecureForTests bool
	STUNTestIP       string
	CanPort80        bool
}{})

// Clone makes a deep copy of SSHRule.
// The result aliases no memory with the original.
func (src *SSHRule) Clone() *SSHRule {
	if src == nil {
		return nil
	}
	dst := new(SSHRule)
	*dst = *src
	if dst.RuleExpires != nil {
		dst.RuleExpires = ptr.To(*src.RuleExpires)
	}
	if src.Principals != nil {
		dst.Principals = make([]*SSHPrincipal, len(src.Principals))
		for i := range dst.Principals {
			dst.Principals[i] = src.Principals[i].Clone()
		}
	}
	dst.SSHUsers = maps.Clone(src.SSHUsers)
	dst.Action = src.Action.Clone()
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _SSHRuleCloneNeedsRegeneration = SSHRule(struct {
	RuleExpires *time.Time
	Principals  []*SSHPrincipal
	SSHUsers    map[string]string
	Action      *SSHAction
}{})

// Clone makes a deep copy of SSHAction.
// The result aliases no memory with the original.
func (src *SSHAction) Clone() *SSHAction {
	if src == nil {
		return nil
	}
	dst := new(SSHAction)
	*dst = *src
	dst.Recorders = append(src.Recorders[:0:0], src.Recorders...)
	if dst.OnRecordingFailure != nil {
		dst.OnRecordingFailure = ptr.To(*src.OnRecordingFailure)
	}
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _SSHActionCloneNeedsRegeneration = SSHAction(struct {
	Message                   string
	Reject                    bool
	Accept                    bool
	SessionDuration           time.Duration
	AllowAgentForwarding      bool
	HoldAndDelegate           string
	AllowLocalPortForwarding  bool
	AllowRemotePortForwarding bool
	AllowLocalUnixForwarding  bool
	AllowRemoteUnixForwarding bool
	Recorders                 []netip.AddrPort
	OnRecordingFailure        *SSHRecorderFailureAction
}{})

// Clone makes a deep copy of SSHPrincipal.
// The result aliases no memory with the original.
func (src *SSHPrincipal) Clone() *SSHPrincipal {
	if src == nil {
		return nil
	}
	dst := new(SSHPrincipal)
	*dst = *src
	dst.PubKeys = append(src.PubKeys[:0:0], src.PubKeys...)
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _SSHPrincipalCloneNeedsRegeneration = SSHPrincipal(struct {
	Node      StableNodeID
	NodeIP    string
	UserLogin string
	Any       bool
	PubKeys   []string
}{})

// Clone makes a deep copy of ControlDialPlan.
// The result aliases no memory with the original.
func (src *ControlDialPlan) Clone() *ControlDialPlan {
	if src == nil {
		return nil
	}
	dst := new(ControlDialPlan)
	*dst = *src
	dst.Candidates = append(src.Candidates[:0:0], src.Candidates...)
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _ControlDialPlanCloneNeedsRegeneration = ControlDialPlan(struct {
	Candidates []ControlIPCandidate
}{})

// Clone makes a deep copy of Location.
// The result aliases no memory with the original.
func (src *Location) Clone() *Location {
	if src == nil {
		return nil
	}
	dst := new(Location)
	*dst = *src
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _LocationCloneNeedsRegeneration = Location(struct {
	Country     string
	CountryCode string
	City        string
	CityCode    string
	Latitude    float64
	Longitude   float64
	Priority    int
}{})

// Clone makes a deep copy of UserProfile.
// The result aliases no memory with the original.
func (src *UserProfile) Clone() *UserProfile {
	if src == nil {
		return nil
	}
	dst := new(UserProfile)
	*dst = *src
	return dst
}

// A compilation failure here means this code must be regenerated, with the command at the top of this file.
var _UserProfileCloneNeedsRegeneration = UserProfile(struct {
	ID            UserID
	LoginName     string
	DisplayName   string
	ProfilePicURL string
	Roles         emptyStructJSONSlice
}{})

// Clone duplicates src into dst and reports whether it succeeded.
// To succeed, <src, dst> must be of types <*T, *T> or <*T, **T>,
// where T is one of User,Node,Hostinfo,NetInfo,Login,DNSConfig,RegisterResponse,RegisterResponseAuth,RegisterRequest,DERPHomeParams,DERPRegion,DERPMap,DERPNode,SSHRule,SSHAction,SSHPrincipal,ControlDialPlan,Location,UserProfile.
func Clone(dst, src any) bool {
	switch src := src.(type) {
	case *User:
		switch dst := dst.(type) {
		case *User:
			*dst = *src.Clone()
			return true
		case **User:
			*dst = src.Clone()
			return true
		}
	case *Node:
		switch dst := dst.(type) {
		case *Node:
			*dst = *src.Clone()
			return true
		case **Node:
			*dst = src.Clone()
			return true
		}
	case *Hostinfo:
		switch dst := dst.(type) {
		case *Hostinfo:
			*dst = *src.Clone()
			return true
		case **Hostinfo:
			*dst = src.Clone()
			return true
		}
	case *NetInfo:
		switch dst := dst.(type) {
		case *NetInfo:
			*dst = *src.Clone()
			return true
		case **NetInfo:
			*dst = src.Clone()
			return true
		}
	case *Login:
		switch dst := dst.(type) {
		case *Login:
			*dst = *src.Clone()
			return true
		case **Login:
			*dst = src.Clone()
			return true
		}
	case *DNSConfig:
		switch dst := dst.(type) {
		case *DNSConfig:
			*dst = *src.Clone()
			return true
		case **DNSConfig:
			*dst = src.Clone()
			return true
		}
	case *RegisterResponse:
		switch dst := dst.(type) {
		case *RegisterResponse:
			*dst = *src.Clone()
			return true
		case **RegisterResponse:
			*dst = src.Clone()
			return true
		}
	case *RegisterResponseAuth:
		switch dst := dst.(type) {
		case *RegisterResponseAuth:
			*dst = *src.Clone()
			return true
		case **RegisterResponseAuth:
			*dst = src.Clone()
			return true
		}
	case *RegisterRequest:
		switch dst := dst.(type) {
		case *RegisterRequest:
			*dst = *src.Clone()
			return true
		case **RegisterRequest:
			*dst = src.Clone()
			return true
		}
	case *DERPHomeParams:
		switch dst := dst.(type) {
		case *DERPHomeParams:
			*dst = *src.Clone()
			return true
		case **DERPHomeParams:
			*dst = src.Clone()
			return true
		}
	case *DERPRegion:
		switch dst := dst.(type) {
		case *DERPRegion:
			*dst = *src.Clone()
			return true
		case **DERPRegion:
			*dst = src.Clone()
			return true
		}
	case *DERPMap:
		switch dst := dst.(type) {
		case *DERPMap:
			*dst = *src.Clone()
			return true
		case **DERPMap:
			*dst = src.Clone()
			return true
		}
	case *DERPNode:
		switch dst := dst.(type) {
		case *DERPNode:
			*dst = *src.Clone()
			return true
		case **DERPNode:
			*dst = src.Clone()
			return true
		}
	case *SSHRule:
		switch dst := dst.(type) {
		case *SSHRule:
			*dst = *src.Clone()
			return true
		case **SSHRule:
			*dst = src.Clone()
			return true
		}
	case *SSHAction:
		switch dst := dst.(type) {
		case *SSHAction:
			*dst = *src.Clone()
			return true
		case **SSHAction:
			*dst = src.Clone()
			return true
		}
	case *SSHPrincipal:
		switch dst := dst.(type) {
		case *SSHPrincipal:
			*dst = *src.Clone()
			return true
		case **SSHPrincipal:
			*dst = src.Clone()
			return true
		}
	case *ControlDialPlan:
		switch dst := dst.(type) {
		case *ControlDialPlan:
			*dst = *src.Clone()
			return true
		case **ControlDialPlan:
			*dst = src.Clone()
			return true
		}
	case *Location:
		switch dst := dst.(type) {
		case *Location:
			*dst = *src.Clone()
			return true
		case **Location:
			*dst = src.Clone()
			return true
		}
	case *UserProfile:
		switch dst := dst.(type) {
		case *UserProfile:
			*dst = *src.Clone()
			return true
		case **UserProfile:
			*dst = src.Clone()
			return true
		}
	}
	return false
}
