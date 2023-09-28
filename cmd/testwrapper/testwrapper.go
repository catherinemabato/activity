// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// testwrapper is a wrapper for retrying flaky tests. It is an alternative to
// `go test` and re-runs failed marked flaky tests (using the flakytest pkg). It
// takes different arguments than go test and requires the first positional
// argument to be the pattern to test.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	xmaps "golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"tailscale.com/cmd/testwrapper/flakytest"
)

const maxAttempts = 3

type testAttempt struct {
	pkg           string // "tailscale.com/types/key"
	testName      string // "TestFoo"
	outcome       string // "pass", "fail", "skip"
	logs          bytes.Buffer
	isMarkedFlaky bool   // set if the test is marked as flaky
	issueURL      string // set if the test is marked as flaky

	pkgFinished bool
}

// packageTests describes what to run.
// It's also JSON-marshalled to output for analysys tools to parse
// so the fields are all exported.
// TODO(bradfitz): move this type to its own types package?
type packageTests struct {
	// Pattern is the package Pattern to run.
	// Must be a single Pattern, not a list of patterns.
	Pattern string // "./...", "./types/key"
	// Tests is a list of Tests to run. If empty, all Tests in the package are
	// run.
	Tests []string // ["TestFoo", "TestBar"]
	// IssueURLs maps from a test name to a URL tracking its flake.
	IssueURLs map[string]string // "TestFoo" => "https://github.com/foo/bar/issue/123"
}

type goTestOutput struct {
	Time    time.Time
	Action  string
	Package string
	Test    string
	Output  string
}

var debug = os.Getenv("TS_TESTWRAPPER_DEBUG") != ""

// runTests runs the tests in pt and sends the results on ch. It sends a
// testAttempt for each test and a final testAttempt per pkg with pkgFinished
// set to true. Package build errors will not emit a testAttempt (as no valid
// JSON is produced) but the [os/exec.ExitError] will be returned.
// It calls close(ch) when it's done.
func runTests(ctx context.Context, attempt int, pt *packageTests, otherArgs []string, ch chan<- *testAttempt) error {
	defer close(ch)
	args := []string{"test", "-json", pt.Pattern}
	args = append(args, otherArgs...)
	if len(pt.Tests) > 0 {
		runArg := strings.Join(pt.Tests, "|")
		args = append(args, "-run", runArg)
	}
	if debug {
		fmt.Println("running", strings.Join(args, " "))
	}
	cmd := exec.CommandContext(ctx, "go", args...)
	r, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("error creating stdout pipe: %v", err)
	}
	defer r.Close()
	cmd.Stderr = os.Stderr

	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%d", flakytest.FlakeAttemptEnv, attempt))

	if err := cmd.Start(); err != nil {
		log.Printf("error starting test: %v", err)
		os.Exit(1)
	}

	s := bufio.NewScanner(r)
	resultMap := make(map[string]map[string]*testAttempt) // pkg -> test -> testAttempt
	for s.Scan() {
		var goOutput goTestOutput
		if err := json.Unmarshal(s.Bytes(), &goOutput); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
				break
			}

			// `go test -json` outputs invalid JSON when a build fails.
			// In that case, discard the the output and start reading again.
			// The build error will be printed to stderr.
			// See: https://github.com/golang/go/issues/35169
			if _, ok := err.(*json.SyntaxError); ok {
				fmt.Println(s.Text())
				continue
			}
			panic(err)
		}
		pkg := goOutput.Package
		pkgTests := resultMap[pkg]
		if goOutput.Test == "" {
			switch goOutput.Action {
			case "fail", "pass", "skip":
				for _, test := range pkgTests {
					if test.outcome == "" {
						test.outcome = "fail"
						ch <- test
					}
				}
				ch <- &testAttempt{
					pkg:         goOutput.Package,
					outcome:     goOutput.Action,
					pkgFinished: true,
				}
			}
			continue
		}
		if pkgTests == nil {
			pkgTests = make(map[string]*testAttempt)
			resultMap[pkg] = pkgTests
		}
		testName := goOutput.Test
		if test, _, isSubtest := strings.Cut(goOutput.Test, "/"); isSubtest {
			testName = test
			if goOutput.Action == "output" {
				resultMap[pkg][testName].logs.WriteString(goOutput.Output)
			}
			continue
		}
		switch goOutput.Action {
		case "start":
			// ignore
		case "run":
			pkgTests[testName] = &testAttempt{
				pkg:      pkg,
				testName: testName,
			}
		case "skip", "pass", "fail":
			pkgTests[testName].outcome = goOutput.Action
			ch <- pkgTests[testName]
		case "output":
			if suffix, ok := strings.CutPrefix(strings.TrimSpace(goOutput.Output), flakytest.FlakyTestLogMessage); ok {
				pkgTests[testName].isMarkedFlaky = true
				pkgTests[testName].issueURL = strings.TrimPrefix(suffix, ": ")
			} else {
				pkgTests[testName].logs.WriteString(goOutput.Output)
			}
		}
	}
	if err := cmd.Wait(); err != nil {
		return err
	}
	if err := s.Err(); err != nil {
		return fmt.Errorf("reading go test stdout: %w", err)
	}
	return nil
}

func main() {
	ctx := context.Background()

	// We only need to parse the -v flag to figure out whether to print the logs
	// for a test. We don't need to parse any other flags, so we just use the
	// flag package to parse the -v flag and then pass the rest of the args
	// through to 'go test'.
	// We run `go test -json` which returns the same information as `go test -v`,
	// but in a machine-readable format. So this flag is only for testwrapper's
	// output.
	v := flag.Bool("v", false, "verbose")

	flag.Usage = func() {
		fmt.Println("usage: testwrapper [testwrapper-flags] [pattern] [build/test flags & test binary flags]")
		fmt.Println()
		fmt.Println("testwrapper-flags:")
		flag.CommandLine.PrintDefaults()
		fmt.Println()
		fmt.Println("examples:")
		fmt.Println("\ttestwrapper -v ./... -count=1")
		fmt.Println("\ttestwrapper ./pkg/foo -run TestBar -count=1")
		fmt.Println()
		fmt.Println("Unlike 'go test', testwrapper requires a package pattern as the first positional argument and only supports a single pattern.")
	}
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 || strings.HasPrefix(args[0], "-") {
		fmt.Println("no pattern specified")
		flag.Usage()
		os.Exit(1)
	} else if len(args) > 1 && !strings.HasPrefix(args[1], "-") {
		fmt.Println("expected single pattern")
		flag.Usage()
		os.Exit(1)
	}
	pattern, otherArgs := args[0], args[1:]

	type nextRun struct {
		tests   []*packageTests
		attempt int // starting at 1
	}

	toRun := []*nextRun{
		{
			tests:   []*packageTests{{Pattern: pattern}},
			attempt: 1,
		},
	}
	printPkgOutcome := func(pkg, outcome string, attempt int) {
		if outcome == "skip" {
			fmt.Printf("?\t%s [skipped/no tests] \n", pkg)
			return
		}
		if outcome == "pass" {
			outcome = "ok"
		}
		if outcome == "fail" {
			outcome = "FAIL"
		}
		if attempt > 1 {
			fmt.Printf("%s\t%s [attempt=%d]\n", outcome, pkg, attempt)
			return
		}
		fmt.Printf("%s\t%s\n", outcome, pkg)
	}

	for len(toRun) > 0 {
		var thisRun *nextRun
		thisRun, toRun = toRun[0], toRun[1:]

		if thisRun.attempt > maxAttempts {
			fmt.Println("max attempts reached")
			os.Exit(1)
		}
		if thisRun.attempt > 1 {
			j, _ := json.Marshal(thisRun.tests)
			fmt.Printf("\n\nAttempt #%d: Retrying flaky tests:\n\nflakytest failures JSON: %s\n\n", thisRun.attempt, j)
		}

		toRetry := make(map[string][]*testAttempt) // pkg -> tests to retry
		for _, pt := range thisRun.tests {
			ch := make(chan *testAttempt)
			runErr := make(chan error, 1)
			go func() {
				defer close(runErr)
				runErr <- runTests(ctx, thisRun.attempt, pt, otherArgs, ch)
			}()

			var failed bool
			for tr := range ch {
				// Go assigns the package name "command-line-arguments" when you
				// `go test FILE` rather than `go test PKG`. It's more
				// convenient for us to to specify files in tests, so fix tr.pkg
				// so that subsequent testwrapper attempts run correctly.
				if tr.pkg == "command-line-arguments" {
					tr.pkg = pattern
				}
				if tr.pkgFinished {
					if tr.outcome == "fail" && len(toRetry[tr.pkg]) == 0 {
						// If a package fails and we don't have any tests to
						// retry, then we should fail. This typically happens
						// when a package times out.
						failed = true
					}
					printPkgOutcome(tr.pkg, tr.outcome, thisRun.attempt)
					continue
				}
				if *v || tr.outcome == "fail" {
					io.Copy(os.Stdout, &tr.logs)
				}
				if tr.outcome != "fail" {
					continue
				}
				if tr.isMarkedFlaky {
					toRetry[tr.pkg] = append(toRetry[tr.pkg], tr)
				} else {
					failed = true
				}
			}
			if failed {
				fmt.Println("\n\nNot retrying flaky tests because non-flaky tests failed.")
				os.Exit(1)
			}

			// If there's nothing to retry and no non-retryable tests have
			// failed then we've probably hit a build error.
			if err := <-runErr; len(toRetry) == 0 && err != nil {
				var exit *exec.ExitError
				if errors.As(err, &exit) {
					if code := exit.ExitCode(); code > -1 {
						os.Exit(exit.ExitCode())
					}
				}
				log.Printf("testwrapper: %s", err)
				os.Exit(1)
			}
		}
		if len(toRetry) == 0 {
			continue
		}
		pkgs := xmaps.Keys(toRetry)
		sort.Strings(pkgs)
		nextRun := &nextRun{
			attempt: thisRun.attempt + 1,
		}
		for _, pkg := range pkgs {
			tests := toRetry[pkg]
			slices.SortFunc(tests, func(a, b *testAttempt) int { return strings.Compare(a.testName, b.testName) })
			issueURLs := map[string]string{} // test name => URL
			var testNames []string
			for _, ta := range tests {
				issueURLs[ta.testName] = ta.issueURL
				testNames = append(testNames, ta.testName)
			}
			nextRun.tests = append(nextRun.tests, &packageTests{
				Pattern:   pkg,
				Tests:     testNames,
				IssueURLs: issueURLs,
			})
		}
		toRun = append(toRun, nextRun)
	}
}
