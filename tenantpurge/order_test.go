// SPDX-License-Identifier: Apache-2.0

package tenantpurge

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func ref(n string) TableRef { return TableRef{Schema: "public", Name: n} }

func names(rs []TableRef) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.Name
	}
	return out
}

func TestOrderForDeleteChildrenFirst(t *testing.T) {
	tables := []TableRef{ref("orders"), ref("order_lines"), ref("customers"), ref("notes"), ref("line_tax")}
	edges := []FKEdge{
		{Child: ref("order_lines"), Parent: ref("orders")},
		{Child: ref("orders"), Parent: ref("customers")},
		{Child: ref("line_tax"), Parent: ref("order_lines")},
		{Child: ref("order_lines"), Parent: ref("orders")}, // duplicate constraint
		{Child: ref("orders"), Parent: ref("orders")},      // self reference
		{Child: ref("orders"), Parent: ref("other")},       // outside the set
	}
	ordered, cyclic := OrderForDelete(tables, edges)
	assert.Empty(t, cyclic)
	assert.Equal(t, []string{"line_tax", "notes", "order_lines", "orders", "customers"}, names(ordered))
}

func TestOrderForDeleteDeterministicWithoutEdges(t *testing.T) {
	ordered, cyclic := OrderForDelete([]TableRef{ref("b"), ref("c"), ref("a")}, nil)
	assert.Empty(t, cyclic)
	assert.Equal(t, []string{"a", "b", "c"}, names(ordered))
}

func TestOrderForDeleteCycle(t *testing.T) {
	tables := []TableRef{ref("a"), ref("b"), ref("leaf"), ref("root")}
	edges := []FKEdge{
		{Child: ref("a"), Parent: ref("b")},
		{Child: ref("b"), Parent: ref("a")},
		{Child: ref("leaf"), Parent: ref("a")},
		{Child: ref("root"), Parent: ref("root")},
	}
	ordered, cyclic := OrderForDelete(tables, edges)
	assert.Equal(t, []string{"a", "b"}, names(cyclic))
	assert.Equal(t, []string{"leaf", "root", "a", "b"}, names(ordered))
}
