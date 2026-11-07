// SPDX-License-Identifier: Apache-2.0

// Command gateway is the lab's LLM gateway (ADR-0038): it serves the role aliases
// of a rendered gateway/gateway.json in front of OpenAI-compatible and Anthropic backends. See
// docs/gateway.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/homelab-next/homelab-next/orchestrator/internal/gateway"
)

type options struct {
	config, listen, usage     string
	tlsCert, tlsKey, proxy    string
	upstreamTimeout           time.Duration
	reserveTokens             int
	writeTimeout              time.Duration
	maxInFlight, maxPerKey    int
	maxReplyBytes             int64
	maxReplyBytesPerKey       int64
	allowPlaintext, checkOnly bool
	conformance               bool
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.LookupEnv, nil))
}

// run is the command. ln, when not nil, is the listener to serve on (a test passes one bound to
// -listen's address); otherwise the gateway listens on -listen itself.
func run(args []string, stdout, stderr io.Writer, lookup func(string) (string, bool), ln net.Listener) int {
	fs := flag.NewFlagSet("gateway", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o options
	fs.StringVar(&o.config, "config", "", "path of the rendered gateway.json (required)")
	fs.StringVar(&o.listen, "listen", "127.0.0.1:4100", "listen address") // no-raw-endpoint: allow the loopback listen default, a bind and never a dial (ADR-0038 decision 3)
	fs.StringVar(&o.usage, "usage", "", "path of the usage JSON-lines file (required to serve)")
	fs.DurationVar(&o.upstreamTimeout, "upstream-timeout", gateway.DefaultUpstreamTimeout,
		"bound on one upstream attempt (a stream: on each wait for its next event)")
	fs.IntVar(&o.reserveTokens, "reserve-tokens", gateway.DefaultReserveTokens,
		"output tokens a call reserves on token and cost limits when neither the request's max_tokens nor the role's max_context_tokens bounds it")
	fs.DurationVar(&o.writeTimeout, "write-timeout", gateway.DefaultWriteTimeout,
		"bound on each write to the caller: a whole non-streamed reply, or one streamed event")
	fs.IntVar(&o.maxInFlight, "max-inflight", gateway.DefaultMaxInFlight, "model calls in flight at once, in all")
	fs.IntVar(&o.maxPerKey, "max-inflight-per-key", gateway.DefaultMaxInFlightPerKey, "model calls in flight at once per caller key")
	fs.Int64Var(&o.maxReplyBytes, "max-reply-bytes-inflight", gateway.DefaultMaxReplyBytesInFlight,
		"bytes all non-streamed replies being read may hold at once (over it: 503 overloaded)")
	fs.Int64Var(&o.maxReplyBytesPerKey, "max-reply-bytes-inflight-per-key", 0,
		"one caller key's share of -max-reply-bytes-inflight (0: a quarter of it)")
	fs.StringVar(&o.tlsCert, "tls-cert", "", "TLS certificate file (with -tls-key)")
	fs.StringVar(&o.tlsKey, "tls-key", "", "TLS key file (with -tls-cert)")
	fs.BoolVar(&o.allowPlaintext, "allow-plaintext", false,
		"allow a non-loopback listen without TLS: bearer tokens and prompts then cross that segment in clear")
	fs.StringVar(&o.proxy, "upstream-proxy", "", "HTTP(S) proxy URL for cloud deployments only (none by default; the environment's proxy variables are never read)")
	fs.BoolVar(&o.conformance, "conformance", false,
		"serve a config rendered with conformance_only: true (test only; loopback listen only)")
	fs.BoolVar(&o.checkOnly, "check", false, "load the config and its environment, report the problems, exit 0 or 1")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	log := slog.New(slog.NewTextHandler(stderr, nil))
	cfg, secrets, err := load(o.config, lookup)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if cfg.ConformanceOnly && !o.conformance {
		fmt.Fprintln(stderr, "gateway: the config is conformance_only (a test rendering): refusing to serve it without -conformance")
		return 1
	}
	if err := checkServing(o); err != nil {
		fmt.Fprintln(stderr, "gateway:", err)
		return 1
	}
	if o.checkOnly {
		fmt.Fprintf(stdout, "gateway config ok: %d roles, %d keys\n", len(cfg.Roles), len(cfg.Keys))
		return 0
	}
	if o.usage == "" {
		fmt.Fprintln(stderr, "gateway: -usage is required")
		return 2
	}
	usage, err := gateway.OpenUsageLogWith(o.usage, gateway.UsageOptions{Logger: log})
	if err != nil {
		fmt.Fprintln(stderr, "gateway: usage log:", err)
		return 1
	}
	defer usage.Close()
	var proxy *url.URL
	if o.proxy != "" {
		proxy, _ = url.Parse(o.proxy) // checked in checkServing
	}
	srv := &http.Server{
		Addr: o.listen,
		Handler: gateway.New(gateway.Options{Config: cfg, Secrets: secrets, Usage: usage,
			UpstreamTimeout: o.upstreamTimeout, ReserveTokens: o.reserveTokens,
			WriteTimeout: o.writeTimeout, MaxInFlight: o.maxInFlight, MaxInFlightPerKey: o.maxPerKey,
			MaxReplyBytesInFlight: o.maxReplyBytes, MaxReplyBytesInFlightPerKey: o.maxReplyBytesPerKey, LocalClient: gateway.NewUpstreamClient(nil),
			CloudClient: gateway.NewUpstreamClient(proxy), Logger: log}),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	errc := make(chan error, 1)
	go func() {
		log.Info("gateway listening", "addr", o.listen, "roles", len(cfg.Roles), "tls", o.tlsCert != "")
		switch {
		case ln != nil && o.tlsCert != "":
			errc <- srv.ServeTLS(ln, o.tlsCert, o.tlsKey)
		case ln != nil:
			errc <- srv.Serve(ln)
		case o.tlsCert != "":
			errc <- srv.ListenAndServeTLS(o.tlsCert, o.tlsKey)
		default:
			errc <- srv.ListenAndServe()
		}
	}()
	select {
	case err := <-errc:
		fmt.Fprintln(stderr, "gateway:", err)
		return 1
	case <-ctx.Done():
	}
	log.Info("shutting down: draining in-flight calls")
	sctx, cancel := context.WithTimeout(context.Background(), o.upstreamTimeout+5*time.Second)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		fmt.Fprintln(stderr, "gateway: shutdown:", err)
		return 1
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(stderr, "gateway:", err)
		return 1
	}
	return 0
}

func load(path string, lookup func(string) (string, bool)) (*gateway.Config, *gateway.Secrets, error) {
	if path == "" {
		return nil, nil, errors.New("gateway: -config is required")
	}
	cfg, err := gateway.LoadConfig(path)
	if err != nil {
		return nil, nil, err
	}
	secrets, err := gateway.LoadSecrets(cfg, lookup)
	if err != nil {
		return nil, nil, err
	}
	return cfg, secrets, nil
}

// checkServing refuses flag combinations that cannot serve safely (ADR-0038 d3).
func checkServing(o options) error {
	if (o.tlsCert == "") != (o.tlsKey == "") {
		return errors.New("-tls-cert and -tls-key go together")
	}
	if o.upstreamTimeout <= 0 {
		return errors.New("-upstream-timeout must be positive")
	}
	if o.writeTimeout <= 0 || o.maxInFlight <= 0 || o.maxPerKey <= 0 || o.maxReplyBytes <= 0 {
		return errors.New("-write-timeout, -max-inflight, -max-inflight-per-key and -max-reply-bytes-inflight must be positive")
	}
	if o.maxReplyBytesPerKey < 0 || o.maxReplyBytesPerKey > o.maxReplyBytes {
		return errors.New("-max-reply-bytes-inflight-per-key must be between 0 and -max-reply-bytes-inflight")
	}
	if o.reserveTokens <= 0 {
		return errors.New("-reserve-tokens must be positive")
	}
	if o.proxy != "" {
		u, err := url.Parse(o.proxy)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return errors.New("-upstream-proxy is not an http(s) URL")
		}
	}
	host, _, err := net.SplitHostPort(o.listen)
	if err != nil {
		return fmt.Errorf("-listen %q: %v", o.listen, err)
	}
	if o.conformance && !loopback(host) {
		return fmt.Errorf("-conformance serves loopback only, not %q", o.listen)
	}
	if !loopback(host) && o.tlsCert == "" && !o.allowPlaintext {
		return fmt.Errorf("-listen %q is not loopback: give -tls-cert/-tls-key, or -allow-plaintext when TLS is terminated in front of the gateway", o.listen)
	}
	return nil
}

// lookupIP resolves a listen host name; tests replace it.
var lookupIP = func(host string) ([]net.IP, error) { return net.LookupIP(host) }

// loopback says whether host is a loopback address. A name (localhost included: /etc/hosts or
// the resolver decide what it is) is resolved, and is loopback only when every address it
// resolves to is.
func loopback(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	if host == "" {
		return false
	}
	ips, err := lookupIP(host)
	if err != nil || len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if !ip.IsLoopback() {
			return false
		}
	}
	return true
}
