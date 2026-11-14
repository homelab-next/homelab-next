// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

type tlpVector struct {
	Role          string  `json:"role"`
	SenderCeiling string  `json:"sender_ceiling"`
	Header        *string `json:"header"`
	Allowed       bool    `json:"allowed"`
	Reason        string  `json:"reason"`
	Label         string  `json:"label"`
	Ceiling       string  `json:"ceiling"`
	LeavesLab     bool    `json:"leaves_lab"`
}

// tlpVectors is the repository's own conformance/fixtures/tlp_admit_vectors.json, which the
// Python tests regenerate from homelabnext.model_tlp.admit (ADR-0038 decision 5). It is read in
// place, never copied, so the Go and the Python implementations always judge the same vectors.
const tlpVectors = "../../../conformance/fixtures/tlp_admit_vectors.json"

// TestGatewayTLPAdmitVectors runs every vector of tlpVectors. Ceiling and leaves_lab come from
// the vector: they are what the rendered config carries for the role.
func TestGatewayTLPAdmitVectors(t *testing.T) {
	data, err := os.ReadFile(tlpVectors)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Labels  []string    `json:"labels"`
		Vectors []tlpVector `json:"vectors"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) < 200 {
		t.Fatalf("only %d vectors", len(file.Vectors))
	}
	for i, name := range file.Labels {
		if l, ok := ParseCanonical(name); !ok || l.rank() != i {
			t.Fatalf("label %s: rank %d, want %d", name, l.rank(), i)
		}
	}
	for i, v := range file.Vectors {
		ceiling, ok1 := ParseCanonical(v.Ceiling)
		sender, ok2 := ParseCanonical(v.SenderCeiling)
		if !ok1 || !ok2 {
			t.Fatalf("vector %d: labels %q %q", i, v.Ceiling, v.SenderCeiling)
		}
		var fields []string
		if v.Header != nil {
			fields = []string{*v.Header}
		}
		a := Admit(ceiling, v.LeavesLab, sender, fields)
		hdr := "<none>"
		if v.Header != nil {
			hdr = fmt.Sprintf("%q", *v.Header)
		}
		if a.Allowed != v.Allowed || a.Reason != v.Reason || a.Label.String() != v.Label {
			t.Errorf("vector %d (%s, sender %s, header %s): got %v/%s/%s, want %v/%s/%s", i, v.Role,
				v.SenderCeiling, hdr, a.Allowed, a.Reason, a.Label, v.Allowed, v.Reason, v.Label)
		}
	}
}

func TestGatewayTLPZeroValueIsRed(t *testing.T) {
	var l Label
	if l != Red || l.String() != "red" {
		t.Fatalf("zero Label is %s", l)
	}
	if !Clear.AtOrBelow(Red) || Red.AtOrBelow(Amber) || Stricter(Green, AmberStrict) != AmberStrict {
		t.Fatal("ordering")
	}
}

func TestGatewayTLPHeaderFields(t *testing.T) {
	// ADR-0038 d5: no field is unlabelled; one empty field and several fields are red, above-ceiling.
	cases := []struct {
		fields []string
		reason string
	}{
		{nil, ReasonUnlabelled},
		{[]string{""}, ReasonAbove},
		{[]string{"clear", "clear"}, ReasonAbove},
	}
	for _, c := range cases {
		a := Admit(Green, false, Clear, c.fields)
		if a.Allowed || a.Reason != c.reason || a.Label != Red {
			t.Errorf("%q: %+v", c.fields, a)
		}
	}
	if a := Admit(Green, false, Red, []string{"TLP:CLEAR"}); !a.Allowed || a.Label != Clear {
		t.Errorf("in-lab role judged at its own label: %+v", a)
	}
	if a := Admit(Green, true, Red, []string{"clear"}); a.Allowed || a.Label != Red {
		t.Errorf("leaves-lab role raised to the sender: %+v", a)
	}
}
