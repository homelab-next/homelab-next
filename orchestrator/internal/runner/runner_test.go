// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"errors"
	"fmt"
	"testing"
)

func TestClasses_AreErrorsIsTargetsAndKeepTheText(t *testing.T) {
	base := errors.New("session failed: exit status 1 (stderr: connection refused)")
	inner := Wrap(BackendFault, MarkAbsent(base))
	outer := fmt.Errorf("cloud leg failed after the local one (%w): %w", Wrap(TimeoutCeiling, inner), Wrap(Stalled, errors.New("x")))
	if inner.Error() != base.Error() {
		t.Fatalf("classifying changed the text: %q", inner.Error())
	}
	for _, c := range []Class{BackendFault, TimeoutCeiling, Stalled} {
		if !errors.Is(outer, c) {
			t.Errorf("errors.Is(outer, %v) = false", c)
		}
	}
	for _, c := range []Class{ContextExceeded, TurnCap, Internal} {
		if errors.Is(outer, c) {
			t.Errorf("errors.Is(outer, %v) = true", c)
		}
	}
	if !LooksAbsent(outer) || LooksAbsent(Wrap(Stalled, errors.New("x"))) || LooksAbsent(nil) {
		t.Error("LooksAbsent must find the Absent hint and only it")
	}
	if got := ClassOf(Wrap(TimeoutCeiling, inner)); got != TimeoutCeiling {
		t.Errorf("ClassOf = %v, want the outermost class", got)
	}
	if got := ClassOf(MarkAbsent(Wrap(TurnFailed, base))); got != TurnFailed {
		t.Errorf("ClassOf past an unclassified Absent marker = %v, want TurnFailed", got)
	}
	if ClassOf(base) != Internal || ClassOf(nil) != Internal || Wrap(Stalled, nil) != nil || MarkAbsent(nil) != nil {
		t.Error("an unclassified or nil error is Internal; wrapping nil is nil")
	}
	// an Internal *Error is no errors.Is target for Internal: "no class" never matches
	if errors.Is(&Error{Class: Internal, Err: base}, Internal) {
		t.Error("errors.Is matched Internal")
	}
}

// TestClassOf_PreOrderAndBareClasses: ClassOf finds a bare Class wrapped with %w as well as a
// *Error, and returns the first class in pre-order (each error before what it wraps, joined
// branches left to right).
func TestClassOf_PreOrderAndBareClasses(t *testing.T) {
	if got := ClassOf(fmt.Errorf("turn: %w", TurnCap)); got != TurnCap {
		t.Errorf("bare class = %v, want TurnCap", got)
	}
	joined := fmt.Errorf("local (%w), cloud (%w)", Wrap(Stalled, errors.New("a")), fmt.Errorf("x: %w", KilledExternally))
	if got := ClassOf(joined); got != Stalled {
		t.Errorf("joined = %v, want the left branch's Stalled", got)
	}
	if got := ClassOf(errors.Join(errors.New("plain"), fmt.Errorf("y: %w", ContextExceeded))); got != ContextExceeded {
		t.Errorf("errors.Join = %v, want the classified branch", got)
	}
	if got := ClassOf(Wrap(TimeoutCeiling, fmt.Errorf("y: %w", TurnFailed))); got != TimeoutCeiling {
		t.Errorf("nested = %v, want the outer TimeoutCeiling", got)
	}
	if got := ClassOf(fmt.Errorf("z: %w", Internal)); got != Internal {
		t.Errorf("bare Internal = %v", got)
	}
}

func TestClass_NamesAreDistinct(t *testing.T) {
	seen := map[string]bool{}
	for c := Internal; c <= KilledExternally; c++ {
		n := c.String()
		if n == "" || seen[n] || c.Error() != "runner: "+n {
			t.Errorf("class %d: name %q", int(c), n)
		}
		seen[n] = true
	}
	if Class(99).String() != "class(99)" || Class(-1).String() != "class(-1)" {
		t.Error("an unknown class is named by its number")
	}
}

func TestToolsets_SplitJoinIsExact(t *testing.T) {
	for _, s := range []string{"", "a", "a,b", "a, b", ",a,", "files,notes"} {
		if got := JoinToolsets(SplitToolsets(s)); got != s {
			t.Errorf("Join(Split(%q)) = %q", s, got)
		}
	}
	if SplitToolsets("") != nil {
		t.Error(`Split("") must be nil`)
	}
}
