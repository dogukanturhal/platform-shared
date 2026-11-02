// SPDX-License-Identifier: Apache-2.0

package tenantpurge

import "sort"

// TableRef names a table.
type TableRef struct {
	Schema string
	Name   string
}

func (t TableRef) String() string { return t.Schema + "." + t.Name }

// FKEdge says Child has a foreign key to Parent.
type FKEdge struct {
	Child  TableRef
	Parent TableRef
}

// OrderForDelete returns tables in an order where every table comes before the
// tables it references (children first). Edges that touch a table outside the
// set, and self references, are ignored. Tables caught in a reference cycle are
// appended last in name order and also returned in cyclic so the caller can log
// it; the delete runs with constraints deferred, so deferrable cycles still work
// and anything else fails loudly.
func OrderForDelete(tables []TableRef, edges []FKEdge) (ordered, cyclic []TableRef) {
	set := make(map[TableRef]struct{}, len(tables))
	for _, t := range tables {
		set[t] = struct{}{}
	}
	// children[parent] = distinct tables referencing it; parents[child] likewise.
	children := make(map[TableRef]map[TableRef]struct{})
	parents := make(map[TableRef][]TableRef)
	for _, e := range edges {
		if e.Child == e.Parent {
			continue
		}
		if _, ok := set[e.Child]; !ok {
			continue
		}
		if _, ok := set[e.Parent]; !ok {
			continue
		}
		if children[e.Parent] == nil {
			children[e.Parent] = make(map[TableRef]struct{})
		}
		if _, dup := children[e.Parent][e.Child]; dup {
			continue
		}
		children[e.Parent][e.Child] = struct{}{}
		parents[e.Child] = append(parents[e.Child], e.Parent)
	}

	remaining := make(map[TableRef]int, len(set))
	for t := range set {
		remaining[t] = len(children[t])
	}
	done := make(map[TableRef]bool, len(set))
	for {
		var layer []TableRef
		for t := range set {
			if !done[t] && remaining[t] == 0 {
				layer = append(layer, t)
			}
		}
		if len(layer) == 0 {
			break
		}
		sortRefs(layer)
		for _, t := range layer {
			done[t] = true
			ordered = append(ordered, t)
			for _, p := range parents[t] {
				remaining[p]--
			}
		}
	}
	for t := range set {
		if !done[t] {
			cyclic = append(cyclic, t)
		}
	}
	sortRefs(cyclic)
	ordered = append(ordered, cyclic...)
	return ordered, cyclic
}

func sortRefs(r []TableRef) {
	sort.Slice(r, func(i, j int) bool { return r[i].String() < r[j].String() })
}
