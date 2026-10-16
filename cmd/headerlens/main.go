package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Shell-I-Byte/headerlens/internal/analyzer"
	"github.com/Shell-I-Byte/headerlens/internal/report"
)

var version = "0.1.21-rc11"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("headerlens", flag.ContinueOnError)
	// Avoid echoing untrusted CLI option bytes (including ANSI, bidi and newlines)
	// into terminals or CI logs. Usage is a fixed, trusted diagnostic below.
	fs.SetOutput(io.Discard)
	jsonOut := fs.Bool("json", false, "emit versioned JSON")
	timeout := fs.Duration("timeout", 10*time.Second, "overall request timeout")
	maxRedirects := fs.Int("max-redirects", 10, "maximum redirects to follow; 0 disables redirect following")
	maxHeaderBytes := fs.Int64("max-header-bytes", 1<<20, "maximum response header bytes")
	allowCrossHost := fs.Bool("allow-cross-host-redirects", false, "follow redirects to another hostname (only for explicitly authorized destinations)")
	allowCrossPort := fs.Bool("allow-cross-port-redirects", false, "follow redirects to another effective port (only for explicitly authorized services)")
	allowDowngrade := fs.Bool("allow-downgrade-redirects", false, "follow HTTPS-to-HTTP redirects")
	proxyEnv := fs.Bool("proxy-env", false, "honor HTTP_PROXY/HTTPS_PROXY/NO_PROXY environment variables")
	includeSensitiveHeaders := fs.Bool("include-sensitive-headers", false, "include raw sensitive response metadata in JSON output (including Set-Cookie, authentication field values, and server redirect URL userinfo/query/fragment material)")
	showVersion := fs.Bool("version", false, "print version")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: headerlens [options] https://example.com\n\nOptions:\n")
		// Defaults contain only trusted static flag definitions. Restore the
		// caller sink temporarily so -h/usage remains informative.
		fs.SetOutput(stderr)
		fs.PrintDefaults()
		fs.SetOutput(io.Discard)
	}
	if err := fs.Parse(args); err != nil {
		// The flag package already printed trusted usage for -h/-help.
		// Help is a successful informational invocation, not malformed input.
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, "headerlens: invalid command-line option")
		return 2
	}
	if *showVersion {
		n, err := fmt.Fprintln(stdout, version)
		if err != nil || n != len(version)+1 {
			fmt.Fprintln(stderr, "headerlens: unable to write version")
			return 1
		}
		return 0
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	if *timeout <= 0 {
		fmt.Fprintln(stderr, "headerlens: -timeout must be > 0")
		return 2
	}
	if *maxRedirects < 0 {
		fmt.Fprintln(stderr, "headerlens: -max-redirects must be >= 0")
		return 2
	}
	if *maxHeaderBytes <= 0 {
		fmt.Fprintln(stderr, "headerlens: -max-header-bytes must be > 0")
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	res, err := analyzer.Analyze(ctx, fs.Arg(0), analyzer.Options{
		Timeout:                 *timeout,
		MaxRedirects:            *maxRedirects,
		UserAgent:               "HeaderLens/" + version,
		ToolVersion:             version,
		AllowCrossHostRedirects: *allowCrossHost,
		AllowCrossPortRedirects: *allowCrossPort,
		AllowDowngradeRedirects: *allowDowngrade,
		UseEnvironmentProxy:     *proxyEnv,
		IncludeSensitiveHeaders: *includeSensitiveHeaders,
		MaxResponseHeaderBytes:  *maxHeaderBytes,
	})
	if err != nil {
		fmt.Fprintln(stderr, "headerlens:", err)
		return 1
	}
	if *jsonOut {
		if err := report.JSON(stdout, res); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	} else {
		if err := report.Text(stdout, res); err != nil {
			fmt.Fprintln(stderr, "headerlens: unable to write text report")
			return 1
		}
	}
	return 0
}
