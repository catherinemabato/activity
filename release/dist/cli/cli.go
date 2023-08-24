// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package cli provides the skeleton of a CLI for building release packages.
package cli

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/clientupdate/distsign"
	"tailscale.com/release/dist"
)

// CLI returns a CLI root command to build release packages.
//
// getTargets is a function that gets run in the Exec function of commands that
// need to know the target list. Its execution is deferred in this way to allow
// customization of command FlagSets with flags that influence the target list.
func CLI(getTargets func() ([]dist.Target, error)) *ffcli.Command {
	return &ffcli.Command{
		Name:       "dist",
		ShortUsage: "dist [flags] <command> [command flags]",
		ShortHelp:  "Build tailscale release packages for distribution",
		LongHelp:   `For help on subcommands, add --help after: "dist list --help".`,
		Subcommands: []*ffcli.Command{
			{
				Name: "list",
				Exec: func(ctx context.Context, args []string) error {
					targets, err := getTargets()
					if err != nil {
						return err
					}
					return runList(ctx, args, targets)
				},
				ShortUsage: "dist list [target filters]",
				ShortHelp:  "List all available release targets.",
				LongHelp: strings.TrimSpace(`
			If filters are provided, only targets matching at least one filter are listed.
			Filters can use glob patterns (* and ?).
			`),
			},
			{
				Name: "build",
				Exec: func(ctx context.Context, args []string) error {
					targets, err := getTargets()
					if err != nil {
						return err
					}
					return runBuild(ctx, args, targets)
				},
				ShortUsage: "dist build [target filters]",
				ShortHelp:  "Build release files",
				FlagSet: (func() *flag.FlagSet {
					fs := flag.NewFlagSet("build", flag.ExitOnError)
					fs.StringVar(&buildArgs.manifest, "manifest", "", "manifest file to write")
					fs.BoolVar(&buildArgs.verbose, "verbose", false, "verbose logging")
					fs.StringVar(&buildArgs.webClientRoot, "web-client-root", "", "path to root of web client source to build")
					return fs
				})(),
				LongHelp: strings.TrimSpace(`
			If filters are provided, only targets matching at least one filter are built.
			Filters can use glob patterns (* and ?).
			`),
			},
			{
				Name: "gen-key",
				Exec: func(ctx context.Context, args []string) error {
					return runGenKey(ctx)
				},
				ShortUsage: "dist gen-key",
				ShortHelp:  "Generate root or signing key pair",
				FlagSet: (func() *flag.FlagSet {
					fs := flag.NewFlagSet("gen-key", flag.ExitOnError)
					fs.BoolVar(&genKeyArgs.root, "root", false, "generate a root key")
					fs.BoolVar(&genKeyArgs.signing, "signing", false, "generate a signing key")
					fs.StringVar(&genKeyArgs.privPath, "priv-path", "private-key.pem", "output path for the private key")
					fs.StringVar(&genKeyArgs.pubPath, "pub-path", "public-key.pem", "output path for the public key")
					return fs
				})(),
			},
		},
		Exec: func(context.Context, []string) error { return flag.ErrHelp },
	}
}

func runList(ctx context.Context, filters []string, targets []dist.Target) error {
	if len(filters) == 0 {
		filters = []string{"all"}
	}
	tgts, err := dist.FilterTargets(targets, filters)
	if err != nil {
		return err
	}
	for _, tgt := range tgts {
		fmt.Println(tgt)
	}
	return nil
}

var buildArgs struct {
	manifest      string
	verbose       bool
	webClientRoot string
}

func runBuild(ctx context.Context, filters []string, targets []dist.Target) error {
	tgts, err := dist.FilterTargets(targets, filters)
	if err != nil {
		return err
	}
	if len(tgts) == 0 {
		return errors.New("no targets matched (did you mean 'dist build all'?)")
	}

	st := time.Now()
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("getting working directory: %w", err)
	}
	b, err := dist.NewBuild(wd, filepath.Join(wd, "dist"))
	if err != nil {
		return fmt.Errorf("creating build context: %w", err)
	}
	defer b.Close()
	b.Verbose = buildArgs.verbose
	b.WebClientSource = buildArgs.webClientRoot

	out, err := b.Build(tgts)
	if err != nil {
		return fmt.Errorf("building targets: %w", err)
	}

	if buildArgs.manifest != "" {
		// Make the built paths relative to the manifest file.
		manifest, err := filepath.Abs(buildArgs.manifest)
		if err != nil {
			return fmt.Errorf("getting absolute path of manifest: %w", err)
		}
		for i := range out {
			if !filepath.IsAbs(out[i]) {
				out[i] = filepath.Join(b.Out, out[i])
			}
			rel, err := filepath.Rel(filepath.Dir(manifest), out[i])
			if err != nil {
				return fmt.Errorf("making path relative: %w", err)
			}
			out[i] = rel
		}
		if err := os.WriteFile(manifest, []byte(strings.Join(out, "\n")), 0644); err != nil {
			return fmt.Errorf("writing manifest: %w", err)
		}
	}

	fmt.Println("Done! Took", time.Since(st))
	return nil
}

func parseSigningKey(path string) (crypto.Signer, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, rest := pem.Decode(raw)
	if b == nil {
		return nil, fmt.Errorf("failed to decode PEM data in %q", path)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data in %q, please check that the key file was not corrupted", path)
	}
	return x509.ParseECPrivateKey(b.Bytes)
}

var genKeyArgs struct {
	root     bool
	signing  bool
	privPath string
	pubPath  string
}

func runGenKey(ctx context.Context) error {
	var pub, priv []byte
	var err error
	switch {
	case genKeyArgs.root && genKeyArgs.signing:
		return errors.New("only one of --root or --signing can be set")
	case !genKeyArgs.root && !genKeyArgs.signing:
		return errors.New("set either --root or --signing")
	case genKeyArgs.root:
		priv, pub, err = distsign.GenerateRootKey()
	case genKeyArgs.signing:
		priv, pub, err = distsign.GenerateSigningKey()
	}
	if err != nil {
		return err
	}
	if err := os.WriteFile(genKeyArgs.privPath, priv, 0400); err != nil {
		return fmt.Errorf("failed writing private key: %w", err)
	}
	fmt.Println("wrote private key to", genKeyArgs.privPath)
	if err := os.WriteFile(genKeyArgs.pubPath, pub, 0400); err != nil {
		return fmt.Errorf("failed writing public key: %w", err)
	}
	fmt.Println("wrote public key to", genKeyArgs.pubPath)
	return nil
}
