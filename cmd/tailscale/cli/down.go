// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/peterbourgon/ff/v2/ffcli"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn"
)

var downCmd = &ffcli.Command{
	Name:       "down",
	ShortUsage: "down",
	ShortHelp:  "Disconnect from Tailscale",

	Exec: runDown,
}

func runDown(ctx context.Context, args []string) error {
	if len(args) > 0 {
		log.Fatalf("too many non-flag arguments: %q", args)
	}

	st, err := tailscale.Status(ctx)
	if err != nil {
		return fmt.Errorf("error fetching current status: %w", err)
	}
	if st.BackendState == "Stopped" {
		log.Printf("already stopped")
		return nil
	}
	log.Printf("was in state %q", st.BackendState)

	c, bc, ctx, cancel := connect(ctx)
	defer cancel()

	timer := time.AfterFunc(5*time.Second, func() {
		log.Fatalf("timeout running stop")
	})
	defer timer.Stop()

	bc.SetNotifyCallback(func(n ipn.Notify) {
		if n.ErrMessage != nil {
			log.Fatal(*n.ErrMessage)
		}
		if n.State != nil {
			log.Printf("now in state %q", *n.State)
			if *n.State == ipn.Stopped {
				cancel()
			}
			return
		}
	})

	bc.EditPrefs(&ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			WantRunning: false,
		},
		WantRunningSet: true,
	})
	pump(ctx, bc, c)

	return nil
}
