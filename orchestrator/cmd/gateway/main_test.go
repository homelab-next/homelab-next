// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const config = `{"version":"1.0","name":"t","admin_key_env":"HNX_SECRET_ADMIN","roles":{"r":{"kind":"chat",
"max_context_tokens":null,"tlp_ceiling":"red","leaves_lab":false,"deployments":[{"id":"r-1","backend":"b",
"locality":"local","protocol":"openai","base_url":"http://127.0.0.1:1","model":"m","api_key_env":null}],
"fallbacks":[],"limits":null,"cost_per_1k_tokens":null}},"keys":[],"telemetry_reader":null%s}`

// adminValue is a dummy admin key of the 32-byte minimum.
const adminValue = "the-admin-value-0123456789abcdef0123"

func writeConfig(t *testing.T, extra string) string {
	p := filepath.Join(t.TempDir(), "gateway.json")
	if err := os.WriteFile(p, []byte(strings.Replace(config, "%s", extra, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func runGW(t *testing.T, lookup map[string]string, args ...string) (int, string) {
	var out, errb bytes.Buffer
	code := run(args, &out, &errb, env(lookup), nil)
	return code, out.String() + errb.String()
}

func TestGatewayCmdCheck(t *testing.T) {
	p := writeConfig(t, "")
	good := map[string]string{"HNX_SECRET_ADMIN": adminValue}
	if code, out := runGW(t, good, "-config", p, "-check"); code != 0 || !strings.Contains(out, "ok") {
		t.Fatalf("%d %s", code, out)
	}
	code, out := runGW(t, map[string]string{}, "-config", p, "-check")
	if code != 1 || !strings.Contains(out, "HNX_SECRET_ADMIN") {
		t.Fatalf("missing env: %d %s", code, out)
	}
	bad := writeConfig(t, `,"extra":1`)
	if code, out := runGW(t, good, "-config", bad, "-check"); code != 1 || !strings.Contains(out, "unknown field") {
		t.Fatalf("unknown key: %d %s", code, out)
	}
	if code, _ := runGW(t, good, "-check"); code != 1 {
		t.Fatal("no -config accepted")
	}
}

func TestGatewayCmdLocalhostIsResolved(t *testing.T) {
	p := writeConfig(t, "")
	good := map[string]string{"HNX_SECRET_ADMIN": adminValue}
	saved := lookupIP
	t.Cleanup(func() { lookupIP = saved })
	lookupIP = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, nil }
	if code, out := runGW(t, good, "-config", p, "-check", "-listen", "localhost:4100"); code != 0 {
		t.Fatalf("loopback localhost: %d %s", code, out)
	}
	// a hosts file that maps localhost to a lab address does not make that a loopback listen
	lookupIP = func(string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.0.2.5")}, nil
	}
	if code, out := runGW(t, good, "-config", p, "-check", "-listen", "localhost:4100"); code != 1 || !strings.Contains(out, "not loopback") {
		t.Fatalf("localhost to a lab address: %d %s", code, out)
	}
}

func TestGatewayCmdListenAndConformance(t *testing.T) {
	p := writeConfig(t, "")
	conf := writeConfig(t, `,"conformance_only":true`)
	good := map[string]string{"HNX_SECRET_ADMIN": adminValue}
	for _, c := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"-config", p, "-check", "-listen", "0.0.0.0:4100"}, 1, "not loopback"},
		{[]string{"-config", p, "-check", "-listen", ":4100"}, 1, "not loopback"},
		{[]string{"-config", p, "-check", "-listen", "0.0.0.0:4100", "-allow-plaintext"}, 0, "ok"},
		{[]string{"-config", p, "-check", "-listen", "192.0.2.5:4100", "-tls-cert", "c.pem", "-tls-key", "k.pem"}, 0, "ok"},
		{[]string{"-config", p, "-check", "-tls-cert", "c.pem"}, 1, "go together"},
		{[]string{"-config", p, "-check", "-listen", "[::1]:4100"}, 0, "ok"},
		{[]string{"-config", p, "-check", "-upstream-proxy", "socks5://x"}, 1, "upstream-proxy"},
		{[]string{"-config", conf, "-check"}, 1, "conformance_only"},
		{[]string{"-config", conf, "-check", "-conformance"}, 0, "ok"},
		{[]string{"-config", conf, "-check", "-conformance", "-listen", "0.0.0.0:4100", "-allow-plaintext"}, 1, "loopback only"},
	} {
		code, out := runGW(t, good, c.args...)
		if code != c.code || !strings.Contains(out, c.want) {
			t.Errorf("%v: %d %s", c.args, code, out)
		}
	}
}

func TestGatewayCmdServesAndShutsDownOnSIGTERM(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	addr := ln.Addr().String()
	usage := filepath.Join(t.TempDir(), "usage.jsonl")
	cfg := writeConfig(t, "")
	lookup := env(map[string]string{"HNX_SECRET_ADMIN": adminValue})
	done := make(chan int, 1)
	go func() { // no t helpers in here
		var out, errb bytes.Buffer
		done <- run([]string{"-config", cfg, "-listen", addr, "-usage", usage}, &out, &errb, lookup, ln)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := http.Get("http://" + addr + "/healthz")
		if err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the gateway did not come up")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if st, err := os.Stat(usage); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("usage file: %v", err)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no shutdown on SIGTERM")
	}
}
