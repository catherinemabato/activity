// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux freebsd

package dns

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"

	"tailscale.com/types/logger"
)

// isResolvconfActive indicates whether the system appears to be using resolvconf.
// If this is true, then directManager should be avoided:
// resolvconf has exclusive ownership of /etc/resolv.conf.
func isResolvconfActive() bool {
	// Sanity-check first: if there is no resolvconf binary, then this is fruitless.
	//
	// However, this binary may be a shim like the one systemd-resolved provides.
	// Such a shim may not behave as expected: in particular, systemd-resolved
	// does not seem to respect the exclusive mode -x, saying:
	//   -x            Send DNS traffic preferably over this interface
	// whereas e.g. openresolv sends DNS traffix _exclusively_ over that interface,
	// or not at all (in case of another exclusive-mode request later in time).
	//
	// Moreover, resolvconf may be installed but unused, in which case we should
	// not use it either, lest we clobber existing configuration.
	//
	// To handle all the above correctly, we scan the comments in /etc/resolv.conf
	// to ensure that it was generated by a resolvconf implementation.
	_, err := exec.LookPath("resolvconf")
	if err != nil {
		return false
	}

	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		// Look for the word "resolvconf" until comments end.
		if len(line) > 0 && line[0] != '#' {
			return false
		}
		if bytes.Contains(line, []byte("resolvconf")) {
			return true
		}
	}
	return false
}

// resolvconfImpl enumerates supported implementations of the resolvconf CLI.
type resolvconfImpl uint8

const (
	// resolvconfOpenresolv is the implementation packaged as "openresolv" on Ubuntu.
	// It supports exclusive mode and interface metrics.
	resolvconfOpenresolv resolvconfImpl = iota
	// resolvconfLegacy is the implementation by Thomas Hood packaged as "resolvconf" on Ubuntu.
	// It does not support exclusive mode or interface metrics.
	resolvconfLegacy
)

func (impl resolvconfImpl) String() string {
	switch impl {
	case resolvconfOpenresolv:
		return "openresolv"
	case resolvconfLegacy:
		return "legacy"
	default:
		return "unknown"
	}
}

// getResolvconfImpl returns the implementation of resolvconf that appears to be in use.
func getResolvconfImpl() resolvconfImpl {
	err := exec.Command("resolvconf", "-v").Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Thomas Hood's resolvconf has a minimal flag set
			// and exits with code 99 when passed an unknown flag.
			if exitErr.ExitCode() == 99 {
				return resolvconfLegacy
			}
		}
	}
	return resolvconfOpenresolv
}

type resolvconfManager struct {
	impl resolvconfImpl
}

func newResolvconfManager(logf logger.Logf) resolvconfManager {
	impl := getResolvconfImpl()
	logf("resolvconf implementation is %s", impl)

	return resolvconfManager{
		impl: impl,
	}
}

// resolvconfConfigName is the name of the config submitted to resolvconf.
// It has this form to match the "tun*" rule in interface-order
// when running resolvconfLegacy, hopefully placing our config first.
const resolvconfConfigName = "tun-tailscale.inet"

func (m resolvconfManager) SetDNS(config OSConfig) error {
	stdin := new(bytes.Buffer)
	writeResolvConf(stdin, config.Nameservers, config.SearchDomains) // dns_direct.go

	var cmd *exec.Cmd
	switch m.impl {
	case resolvconfOpenresolv:
		// Request maximal priority (metric 0) and exclusive mode.
		cmd = exec.Command("resolvconf", "-m", "0", "-x", "-a", resolvconfConfigName)
	case resolvconfLegacy:
		// This does not quite give us the desired behavior (queries leak),
		// but there is nothing else we can do without messing with other interfaces' settings.
		cmd = exec.Command("resolvconf", "-a", resolvconfConfigName)
	}
	cmd.Stdin = stdin
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("running %s: %s", cmd, out)
	}

	return nil
}

func (m resolvconfManager) SupportsSplitDNS() bool {
	return false
}

func (m resolvconfManager) GetBaseConfig() (OSConfig, error) {
	return OSConfig{}, ErrGetBaseConfigNotSupported
}

func (m resolvconfManager) Close() error {
	var cmd *exec.Cmd
	switch m.impl {
	case resolvconfOpenresolv:
		cmd = exec.Command("resolvconf", "-f", "-d", resolvconfConfigName)
	case resolvconfLegacy:
		// resolvconfLegacy lacks the -f flag.
		// Instead, it succeeds even when the config does not exist.
		cmd = exec.Command("resolvconf", "-d", resolvconfConfigName)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("running %s: %s", cmd, out)
	}

	return nil
}
