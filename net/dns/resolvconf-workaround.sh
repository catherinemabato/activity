#!/bin/sh
# Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.
#
# This script is a workaround for a vpn-unfriendly behavior of the
# original resolvconf by Thomas Hood. Unlike the `openresolv`
# implementation (whose binary is also called resolvconf,
# confusingly), the original resolvconf lacks a way to specify
# "exclusive mode" for a provider configuration. In practice, this
# means that if Tailscale wants to install a DNS configuration, that
# config will get "blended" with the configs from other sources,
# rather than override those other sources.
#
# This script gets installed at /etc/resolvconf/update-libc.d, which
# is a directory of hook scripts that get run after resolvconf's libc
# helper has finished rewriting /etc/resolv.conf. It's meant to notify
# consumers of resolv.conf of a new configuration.
#
# Instead, we use that hook mechanism to reach into resolvconf's
# stuff, and rewrite the libc-generated resolv.conf to exclusively
# contain Tailscale's configuration - effectively implementing
# exclusive mode ourselves in post-production.

set -e

if [ -n "$TAILSCALE_RESOLVCONF_HOOK_LOOP" ]; then
	# Hook script being invoked by itself, skip.
	exit 0
fi

if [ ! -f tun-tailscale.inet ]; then
	# Tailscale isn't trying to manage DNS, do nothing.
	exit 0
fi

if ! grep resolvconf /etc/resolv.conf >/dev/null; then
	# resolvconf isn't managing /etc/resolv.conf, do nothing.
	exit 0
fi

# Write out a modified /etc/resolv.conf containing just our config.
(
	if [ -f /etc/resolvconf/resolv.conf.d/head ]; then
		cat /etc/resolvconf/resolv.conf.d/head
	fi
	echo "# Tailscale workaround applied to set exclusive DNS configuration."
	cat tun-tailscale.inet
) >/etc/resolv.conf

if [ -d /etc/resolvconf/update-libc.d ] ; then
	# Re-notify libc watchers that we've changed resolv.conf again.
	export TAILSCALE_RESOLVCONF_HOOK_LOOP=1
	exec run-parts /etc/resolvconf/update-libc.d
fi
