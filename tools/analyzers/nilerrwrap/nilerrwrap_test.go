// SPDX-License-Identifier: Apache-2.0

package nilerrwrap_test

import (
	"reflect"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/dogukanturhal/platform-shared/tools/analyzers/nilerrwrap"
)

func TestAnalyzer(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), nilerrwrap.Analyzer, "a", "real")
}

// TestDeterministic runs the analysis repeatedly and requires identical diagnostics.
func TestDeterministic(t *testing.T) {
	render := func() []string {
		var out []string
		for _, r := range analysistest.Run(t, analysistest.TestData(), nilerrwrap.Analyzer, "a", "real") {
			for _, d := range r.Diagnostics {
				out = append(out, r.Pass.Fset.Position(d.Pos).String()+": "+d.Message)
			}
		}
		return out
	}
	first := render()
	if len(first) == 0 {
		t.Fatal("no diagnostics")
	}
	for i := 0; i < 5; i++ {
		got := render()
		if !reflect.DeepEqual(first, got) {
			t.Fatalf("run %d differs:\n%v\nvs\n%v", i, first, got)
		}
	}
}
