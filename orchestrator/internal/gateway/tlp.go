// SPDX-License-Identifier: Apache-2.0

package gateway

import "strings"

// Label is a TLP 2.0 label. Its zero value is Red, so a ceiling that was never set reads as the
// most restrictive label, never as clear (ADR-0038 d5). Compare labels only with AtOrBelow and
// Stricter, never with < (the numeric order is not the restriction order).
type Label uint8

// The five labels.
const (
	Red Label = iota
	AmberStrict
	Amber
	Green
	Clear
)

// labelNames is indexed by restriction rank: clear 0 up to red 4.
var labelNames = [...]string{"clear", "green", "amber", "amber+strict", "red"}

// rank is 0 for clear up to 4 for red; anything unknown is red.
func (l Label) rank() int {
	if l > Clear {
		return 4
	}
	return 4 - int(l)
}

func labelOfRank(r int) Label { return Label(4 - r) }

func (l Label) String() string { return labelNames[l.rank()] }

// AtOrBelow says whether l is no more restrictive than ceiling.
func (l Label) AtOrBelow(ceiling Label) bool { return l.rank() <= ceiling.rank() }

// Stricter is the more restrictive of a and b.
func Stricter(a, b Label) Label {
	if a.rank() >= b.rank() {
		return a
	}
	return b
}

// ParseCanonical reads a label this platform wrote (a config ceiling): only the five canonical
// spellings are labels.
func ParseCanonical(s string) (Label, bool) {
	for r, n := range labelNames {
		if s == n {
			return labelOfRank(r), true
		}
	}
	return Red, false
}

// ReadTLP reads a label carried on data, exactly as homelabnext.tlp.read: ASCII only, surrounding
// space/tab/CR/LF ignored, any case, an optional "tlp:" prefix, "white" is clear. Anything else
// is red. It never fails.
func ReadTLP(value string) Label {
	for i := 0; i < len(value); i++ {
		if value[i] >= 0x80 {
			return Red
		}
	}
	text := strings.ToLower(strings.Trim(value, " \t\r\n"))
	text = strings.TrimPrefix(text, "tlp:")
	if text == "white" {
		return Clear
	}
	if l, ok := ParseCanonical(text); ok {
		return l
	}
	return Red
}

// Admission reasons (homelabnext.model_tlp).
const (
	ReasonWithin     = "within-ceiling"
	ReasonAbove      = "above-ceiling"
	ReasonUnlabelled = "unlabelled"
)

// Admission is whether one request may go to a role, and why.
type Admission struct {
	Allowed bool
	Label   Label // the label the request was judged at
	Reason  string
}

// Admit applies the per-request TLP rule (ADR-0033 decision 11, ADR-0038 decision 5) to the
// X-HNX-TLP header fields of a request: none is red (reason unlabelled when refused),
// exactly one is read as data, more than one is red (above-ceiling).
func Admit(roleCeiling Label, leavesLab bool, sender Label, fields []string) Admission {
	label := Red
	if len(fields) == 1 {
		label = ReadTLP(fields[0])
	}
	if leavesLab {
		label = Stricter(label, sender)
	}
	if label.AtOrBelow(roleCeiling) {
		return Admission{Allowed: true, Label: label, Reason: ReasonWithin}
	}
	reason := ReasonAbove
	if len(fields) == 0 {
		reason = ReasonUnlabelled
	}
	return Admission{Allowed: false, Label: label, Reason: reason}
}
