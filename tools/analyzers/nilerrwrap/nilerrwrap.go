// SPDX-License-Identifier: Apache-2.0

// Package nilerrwrap reports returns of fmt.Errorf that wrap an error which is
// nil on some path reaching the call:
//
//	err := c.Set(k, v)
//	if err != nil {
//		log.Warn("set failed", err)
//	}
//	return fmt.Errorf("Set: %w", err) // always non-nil, even when err == nil
//
// fmt.Errorf never returns nil, so the success path of such a function reports
// failure. The check is SSA based: for a wrapped error value v it looks for a
// way v can be nil (a branch edge taken when v == nil, an incoming nil phi
// edge, or a nil constant) and reports when the Errorf call is reachable from
// that point without crossing an edge that proves v != nil.
package nilerrwrap

import (
	"go/constant"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

var Analyzer = &analysis.Analyzer{
	Name:     "nilerrwrap",
	Doc:      "report fmt.Errorf calls returned while the wrapped error may be nil",
	Requires: []*analysis.Analyzer{buildssa.Analyzer},
	Run:      run,
}

func run(pass *analysis.Pass) (any, error) {
	ssainput := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA)
	seen := map[token.Pos]bool{}
	for _, fn := range ssainput.SrcFuncs {
		for _, b := range fn.Blocks {
			for _, instr := range b.Instrs {
				call, ok := instr.(*ssa.Call)
				if !ok || !isErrorf(call) || !returned(call, 0) {
					continue
				}
				for _, arg := range wrappedErrors(call) {
					if mayBeNil(arg, b) && !seen[call.Pos()] {
						seen[call.Pos()] = true
						pass.Reportf(call.Pos(), "fmt.Errorf wraps an error that may be nil here; the result is non-nil even on the success path")
					}
				}
			}
		}
	}
	return nil, nil
}

func isErrorf(call *ssa.Call) bool {
	fn := call.Call.StaticCallee()
	return fn != nil && fn.Pkg != nil && fn.Pkg.Pkg.Path() == "fmt" && fn.Name() == "Errorf"
}

// returned reports whether v flows (directly or through phis) into a return.
func returned(v ssa.Value, depth int) bool {
	if depth > 3 {
		return false
	}
	for _, r := range *v.Referrers() {
		switch r := r.(type) {
		case *ssa.Return:
			return true
		case *ssa.Phi:
			if returned(r, depth+1) {
				return true
			}
		}
	}
	return false
}

// wrappedErrors returns the error-typed operands consumed by %w, or by %v/%s
// when the operand has an error interface type.
func wrappedErrors(call *ssa.Call) []ssa.Value {
	args := call.Call.Args
	if len(args) != 2 {
		return nil
	}
	format, ok := args[0].(*ssa.Const)
	if !ok || format.Value == nil || format.Value.Kind() != constant.String {
		return nil
	}
	verbs, ok := parseVerbs(constant.StringVal(format.Value))
	if !ok {
		return nil
	}
	elems := variadicElems(args[1])
	var out []ssa.Value
	for i, verb := range verbs {
		if i >= len(elems) || elems[i] == nil {
			continue
		}
		v := elems[i]
		for {
			ci, ok := v.(*ssa.ChangeInterface)
			if !ok {
				break
			}
			v = ci.X
		}
		if !isErrorIface(v.Type()) {
			continue
		}
		if verb == 'w' || verb == 'v' || verb == 's' {
			out = append(out, v)
		}
	}
	return out
}

func isErrorIface(t types.Type) bool {
	if !types.IsInterface(t) {
		return false
	}
	return types.Implements(t, errorType())
}

func errorType() *types.Interface {
	return types.Universe.Lookup("error").Type().Underlying().(*types.Interface)
}

// variadicElems extracts the stored elements of the []any built for a variadic call.
func variadicElems(v ssa.Value) []ssa.Value {
	sl, ok := v.(*ssa.Slice)
	if !ok {
		return nil
	}
	alloc, ok := sl.X.(*ssa.Alloc)
	if !ok {
		return nil
	}
	arr, ok := alloc.Type().Underlying().(*types.Pointer).Elem().Underlying().(*types.Array)
	if !ok {
		return nil
	}
	elems := make([]ssa.Value, arr.Len())
	for _, r := range *alloc.Referrers() {
		ia, ok := r.(*ssa.IndexAddr)
		if !ok {
			continue
		}
		c, ok := ia.Index.(*ssa.Const)
		if !ok {
			continue
		}
		idx := int(c.Int64())
		for _, rr := range *ia.Referrers() {
			if st, ok := rr.(*ssa.Store); ok && st.Addr == ia && idx < len(elems) {
				elems[idx] = st.Val
			}
		}
	}
	return elems
}

// parseVerbs returns the verb letter consuming each successive argument.
// It gives up (ok=false) on explicit indexes or '*' widths.
func parseVerbs(f string) (verbs []rune, ok bool) {
	for i := 0; i < len(f); i++ {
		if f[i] != '%' {
			continue
		}
		i++
		for i < len(f) && containsByte("+-# 0123456789.", f[i]) {
			i++
		}
		if i >= len(f) {
			return verbs, true
		}
		switch f[i] {
		case '%':
		case '*', '[':
			return nil, false
		default:
			verbs = append(verbs, rune(f[i]))
		}
	}
	return verbs, true
}

func containsByte(s string, c byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return true
		}
	}
	return false
}

func isNil(v ssa.Value) bool {
	c, ok := v.(*ssa.Const)
	return ok && c.IsNil()
}

// nilTest classifies the edge pred->succ with respect to v: +1 if v is known
// nil on the edge, -1 if known non-nil, 0 otherwise.
func nilTest(pred, succ *ssa.BasicBlock, v ssa.Value) int {
	if len(pred.Instrs) == 0 || len(pred.Succs) != 2 {
		return 0
	}
	ifi, ok := pred.Instrs[len(pred.Instrs)-1].(*ssa.If)
	if !ok {
		return 0
	}
	bin, ok := ifi.Cond.(*ssa.BinOp)
	if !ok || (bin.Op != token.EQL && bin.Op != token.NEQ) {
		return 0
	}
	if !(same(bin.X, v) && isNil(bin.Y)) && !(same(bin.Y, v) && isNil(bin.X)) {
		return 0
	}
	if pred.Succs[0] == pred.Succs[1] {
		return 0
	}
	trueEdge := succ == pred.Succs[0]
	if (bin.Op == token.EQL) == trueEdge {
		return +1
	}
	return -1
}

func same(a, b ssa.Value) bool {
	for {
		ci, ok := a.(*ssa.ChangeInterface)
		if !ok {
			break
		}
		a = ci.X
	}
	return a == b
}

// mayBeNil reports whether v can be nil when execution reaches block target.
func mayBeNil(v ssa.Value, target *ssa.BasicBlock) bool {
	if isNil(v) {
		return true
	}
	var starts []*ssa.BasicBlock
	// nil edges from branches on v
	if fn := target.Parent(); fn != nil {
		for _, b := range fn.Blocks {
			for _, s := range b.Succs {
				if nilTest(b, s, v) > 0 {
					starts = append(starts, s)
				}
			}
		}
	}
	// nil incoming phi values
	if phi, ok := v.(*ssa.Phi); ok && hasNilPhiEdge(phi, 0) {
		starts = append(starts, phi.Block())
	}
	// a call result nobody has proven non-nil is nil on the success path
	if fn := target.Parent(); fn != nil && len(fn.Blocks) > 0 && isUncheckedCall(v) {
		starts = append(starts, fn.Blocks[0])
	}
	seen := map[*ssa.BasicBlock]bool{}
	for _, s := range starts {
		if reach(s, target, v, seen) {
			return true
		}
	}
	return false
}

func hasNilPhiEdge(phi *ssa.Phi, depth int) bool {
	if depth > 3 {
		return false
	}
	for _, e := range phi.Edges {
		if isNil(e) {
			return true
		}
		if p, ok := e.(*ssa.Phi); ok && hasNilPhiEdge(p, depth+1) {
			return true
		}
	}
	return false
}

// reach does a DFS from start to target, never crossing an edge that proves v != nil.
func reach(start, target *ssa.BasicBlock, v ssa.Value, seen map[*ssa.BasicBlock]bool) bool {
	if start == target {
		return true
	}
	if seen[start] {
		return false
	}
	seen[start] = true
	for _, s := range start.Succs {
		if nilTest(start, s, v) < 0 {
			continue
		}
		if reach(s, target, v, seen) {
			return true
		}
	}
	return false
}

// isUncheckedCall reports whether v is the error result of a call whose callee
// is not known to always return a non-nil error.
func isUncheckedCall(v ssa.Value) bool {
	if ex, ok := v.(*ssa.Extract); ok {
		v = ex.Tuple
	}
	call, ok := v.(*ssa.Call)
	if !ok {
		return false
	}
	if call.Call.IsInvoke() {
		// ctx.Err() is non-nil once ctx.Done() has fired.
		m := call.Call.Method
		return !(m.Name() == "Err" && m.Pkg() != nil && m.Pkg().Path() == "context")
	}
	fn := call.Call.StaticCallee()
	if fn == nil {
		return true
	}
	if fn.Pkg != nil {
		switch fn.Pkg.Pkg.Path() + "." + fn.Name() {
		case "fmt.Errorf", "errors.New":
			return false
		}
	}
	return !strings.HasPrefix(fn.Name(), "New") && !strings.HasPrefix(fn.Name(), "new") && !strings.HasPrefix(fn.Name(), "Err")
}
