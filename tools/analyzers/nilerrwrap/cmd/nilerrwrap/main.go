// SPDX-License-Identifier: Apache-2.0

// Command nilerrwrap runs the nilerrwrap analyzer.
//
//	go run github.com/dogukanturhal/platform-shared/tools/analyzers/nilerrwrap/cmd/nilerrwrap ./...
package main

import (
	"golang.org/x/tools/go/analysis/singlechecker"

	"github.com/dogukanturhal/platform-shared/tools/analyzers/nilerrwrap"
)

func main() { singlechecker.Main(nilerrwrap.Analyzer) }
