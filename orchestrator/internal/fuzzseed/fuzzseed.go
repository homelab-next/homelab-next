// SPDX-License-Identifier: Apache-2.0

// Package fuzzseed holds what the module's fuzz targets share (ADR-0048 decision 1): reading a
// target's committed seed corpus (testdata/fuzz/<target>/, the files go test itself runs) and
// proving that a target's property can fail. It is a test helper: only _test.go files import it,
// which its own test asserts, so nothing here reaches a binary.
//
// Every target keeps its property in a function that takes the reference it compares with, and
// its _test.go holds a deliberately wrong reference beside the right one. HoldsAndCanFail runs
// the seed corpus through both: every seed must satisfy the property against the right reference
// and at least one must break it against the wrong one. A property weakened until it cannot fail
// is then a red test in the blocking go job, deterministically, with no fuzzing run needed.
package fuzzseed

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// header is the first line of every corpus file go test writes and reads.
const header = "go test fuzz v1"

// Corpus returns the inputs of every file under testdata/fuzz/<target> of the calling package,
// in file-name order. A missing directory, an empty one or a file that does not parse fails tb:
// a target's committed corpus is part of its test.
func Corpus(tb testing.TB, target string) [][]any {
	tb.Helper()
	dir := filepath.Join("testdata", "fuzz", target)
	entries, err := os.ReadDir(dir)
	if err != nil {
		tb.Fatalf("the seed corpus of %s: %v", target, err)
	}
	var names []string
	for _, e := range entries {
		if e.Type().IsRegular() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		tb.Fatalf("the seed corpus of %s (%s) is empty", target, dir)
	}
	out := make([][]any, 0, len(names))
	for _, n := range names {
		data, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			tb.Fatal(err)
		}
		args, err := Parse(data)
		if err != nil {
			tb.Fatalf("%s/%s: %v", dir, n, err)
		}
		out = append(out, args)
	}
	return out
}

// Parse reads one corpus file in go test's format: the header line, then one value a line,
// written as a Go conversion (string("a"), []byte("\x00"), bool(true), int(-3), uint(7), byte('x')).
// It reads the types this module's targets take, and refuses any other.
func Parse(data []byte) ([]any, error) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(nil, len(data)+1)
	if !sc.Scan() || strings.TrimSpace(sc.Text()) != header {
		return nil, fmt.Errorf("does not start with %q", header)
	}
	var args []any
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		typ, rest, ok := strings.Cut(line, "(")
		if !ok || !strings.HasSuffix(rest, ")") {
			return nil, fmt.Errorf("%q is not a conversion", line)
		}
		lit := strings.TrimSuffix(rest, ")")
		v, err := value(typ, lit)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", line, err)
		}
		args = append(args, v)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("holds no value")
	}
	return args, nil
}

func value(typ, lit string) (any, error) {
	switch typ {
	case "string":
		return strconv.Unquote(lit)
	case "[]byte":
		s, err := strconv.Unquote(lit)
		return []byte(s), err
	case "bool":
		return strconv.ParseBool(lit)
	case "int":
		n, err := strconv.ParseInt(lit, 0, 64)
		return int(n), err
	case "uint":
		n, err := strconv.ParseUint(lit, 0, 64)
		return uint(n), err
	case "byte", "uint8":
		if strings.HasPrefix(lit, "'") {
			r, _, tail, err := strconv.UnquoteChar(strings.Trim(lit, "'"), '\'')
			if err != nil || tail != "" || r > 0xff {
				return nil, fmt.Errorf("not one byte")
			}
			return byte(r), nil
		}
		n, err := strconv.ParseUint(lit, 0, 8)
		return byte(n), err
	}
	return nil, fmt.Errorf("type %s is not one this module's targets take", typ)
}

// HoldsAndCanFail runs every seed through right and wrong, two checks of one property against
// the right and a deliberately wrong reference. It fails tb when right reports a violation on any
// seed, or when wrong reports none on every seed: then the property, or the corpus, has lost the
// input that shows it can fail.
func HoldsAndCanFail(tb testing.TB, seeds [][]any, right, wrong func(args []any) error) {
	tb.Helper()
	if len(seeds) == 0 {
		tb.Fatal("no seeds")
	}
	caught := 0
	for i, s := range seeds {
		if err := right(s); err != nil {
			tb.Errorf("seed %d %q: %v", i, s, err)
		}
		if wrong(s) != nil {
			caught++
		}
	}
	if caught == 0 {
		tb.Errorf("no seed of %d breaks the property against the wrong reference: the property cannot fail, or the corpus lost its witness", len(seeds))
	}
}
