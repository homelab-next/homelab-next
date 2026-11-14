// SPDX-License-Identifier: Apache-2.0

package scrape

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const body = `# HELP engine:requests_running Requests running.
# TYPE engine:requests_running gauge
engine:requests_running{engine="0",model_name="m"} 5.0
engine:requests_running{engine="1",model_name="m"} 2
engine:requests_waiting{engine="0"} 8 1730000000000
engine:pool_info{block_size="16",note="a \"quoted\", {braced} value\\n",pool_tokens="4096"} 1.0
engine:other 3
engine:broken{engine="0" 9
engine:nan NaN
not a metric line
`

func TestParseReadsTheNamedSamplesOnly(t *testing.T) {
	got, err := Parse(strings.NewReader(body), Names("engine:requests_running", "engine:requests_waiting", "engine:pool_info", "engine:broken", "engine:nan"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("samples = %+v, want 4 (the broken and NaN lines skipped)", got)
	}
	if v, ok := Sum(got, "engine:requests_running", "engine:requests_waiting"); !ok || v != 15 {
		t.Errorf("sum = %v,%v; want 15,true", v, ok)
	}
	info := got[3]
	if info.Labels["pool_tokens"] != "4096" || info.Labels["block_size"] != "16" || info.Labels["note"] != `a "quoted", {braced} value\n` {
		t.Errorf("labels = %#v", info.Labels)
	}
	if _, ok := Sum(got, "engine:other"); ok {
		t.Error("a metric not asked for was read")
	}
	if m, ok := Max(got, "engine:requests_running"); !ok || m != 5 {
		t.Errorf("max = %v,%v", m, ok)
	}
}

func TestParseRefusesARepeatedLabel(t *testing.T) {
	got, _ := Parse(strings.NewReader(`m{a="1",a="2"} 1`+"\n"), nil)
	if len(got) != 0 {
		t.Fatalf("a label set naming a label twice was read: %+v", got)
	}
}

func TestFetchReadsA200AndRefusesEverythingElse(t *testing.T) {
	status := http.StatusOK
	var method string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	got, err := Fetch(context.Background(), srv.Client(), srv.URL, time.Second, Names("engine:requests_waiting"))
	if err != nil || len(got) != 1 || got[0].Value != 8 || method != http.MethodGet {
		t.Fatalf("got %+v, %v (method %s)", got, err, method)
	}
	status = http.StatusBadGateway
	if _, err := Fetch(context.Background(), srv.Client(), srv.URL, time.Second, nil); !errors.Is(err, ErrStatus) {
		t.Errorf("a 502 read as %v, want ErrStatus", err)
	}
}

// The default client follows no redirect: the reading must come from the URL configured.
func TestTheDefaultClientFollowsNoRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirect.Close()
	if _, err := Fetch(context.Background(), NewClient(), redirect.URL, time.Second, nil); !errors.Is(err, ErrStatus) {
		t.Fatalf("a redirect was followed or misread: %v", err)
	}
}

func TestFetchOfADeadEndpointIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	if _, err := Fetch(context.Background(), nil, url, 500*time.Millisecond, nil); err == nil {
		t.Fatal("a closed listener read as a reading")
	}
}

func TestParseBoundsALine(t *testing.T) {
	long := "m{a=\"" + strings.Repeat("x", maxLineBytes) + "\"} 1\n"
	if _, err := Parse(strings.NewReader(long), nil); err == nil {
		t.Fatal("a line past the bound was read")
	}
}

// A body past the bound is no reading: cut there, its last number would be read short (12345 as
// 12). A body of exactly the bound is read.
func TestFetchOfABodyPastTheBoundIsNoReading(t *testing.T) {
	const line = "engine:requests_waiting 12345\n"
	serve := func(body string) *httptest.Server {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(srv.Close)
		return srv
	}
	// comment is n bytes of comment lines of at most 1 KiB each
	comment := func(n int) string {
		var b strings.Builder
		for n > 0 {
			l := min(n, 1024)
			if n-l == 1 { // never leave a remainder too short for "#\n"
				l--
			}
			b.WriteString("#" + strings.Repeat("x", l-2) + "\n")
			n -= l
		}
		return b.String()
	}
	// the bound falls right after "12"
	over := serve(comment(MaxBodyBytes-len("engine:requests_waiting 12")) + line)
	got, err := Fetch(context.Background(), over.Client(), over.URL, 5*time.Second, Names("engine:requests_waiting"))
	if !errors.Is(err, ErrTooLarge) || got != nil {
		t.Fatalf("past the bound: %+v, %v; want no reading", got, err)
	}
	exact := serve(comment(MaxBodyBytes-len(line)) + line)
	got, err = Fetch(context.Background(), exact.Client(), exact.URL, 5*time.Second, Names("engine:requests_waiting"))
	if err != nil || len(got) != 1 || got[0].Value != 12345 {
		t.Fatalf("exactly the bound: %+v, %v", got, err)
	}
}
