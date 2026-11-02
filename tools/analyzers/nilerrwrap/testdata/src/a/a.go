// SPDX-License-Identifier: Apache-2.0

package a

import (
	"context"
	"errors"
	"fmt"
)

func f() error { return nil }

func g() (int, error) { return 0, nil }

// --- positive ---

func logOnly() error {
	err := f()
	if err != nil {
		println("x")
	}
	return fmt.Errorf("wrap: %w", err) // want `may be nil`
}

func unconditional() error {
	err := f()
	return fmt.Errorf("wrap: %w", err) // want `may be nil`
}

func verbV() error {
	err := f()
	if err != nil {
		println("x")
	}
	return fmt.Errorf("wrap: %v", err) // want `may be nil`
}

func multiResult() (int, error) {
	n, err := g()
	if n > 3 {
		return 0, fmt.Errorf("big: %w", err) // want `may be nil`
	}
	return n, nil
}

func nilConst() error {
	var err error
	return fmt.Errorf("wrap: %w", err) // want `may be nil`
}

func phiNil(c bool) error {
	var err error
	if c {
		err = f()
	}
	return fmt.Errorf("wrap: %w", err) // want `may be nil`
}

func namedReturn() (err error) {
	err = f()
	if err != nil {
		println("x")
	}
	return fmt.Errorf("wrap: %w", err) // want `may be nil`
}

func eqNilBranch() error {
	err := f()
	if err == nil {
		println("ok")
	}
	return fmt.Errorf("wrap: %w", err) // want `may be nil`
}

func closure() func() error {
	return func() error {
		err := f()
		return fmt.Errorf("wrap: %w", err) // want `may be nil`
	}
}

func extraArgs(id int) error {
	err := f()
	return fmt.Errorf("id %d: %w", id, err) // want `may be nil`
}

// --- negative ---

func guarded() error {
	err := f()
	if err != nil {
		return fmt.Errorf("wrap: %w", err)
	}
	return nil
}

func earlyNilReturn() error {
	err := f()
	if err == nil {
		return nil
	}
	return fmt.Errorf("wrap: %w", err)
}

func guardAfterLog() error {
	err := f()
	if err != nil {
		println("x")
		return fmt.Errorf("wrap: %w", err)
	}
	return nil
}

func reassigned() error {
	err := f()
	if err == nil {
		err = errors.New("synthetic")
	}
	return fmt.Errorf("wrap: %w", err)
}

func reassignedAlways() error {
	var err error
	err = errors.New("x")
	return fmt.Errorf("wrap: %w", err)
}

func fromNew() error {
	return fmt.Errorf("wrap: %w", errors.New("x"))
}

func loopGuard() error {
	for i := 0; i < 3; i++ {
		err := f()
		if err != nil {
			return fmt.Errorf("iter %d: %w", i, err)
		}
	}
	return nil
}

func namedGuarded() (err error) {
	err = f()
	if err != nil {
		return fmt.Errorf("wrap: %w", err)
	}
	return
}

// deferred wrap: the named result is captured and only wrapped when non-nil.
func deferredGuarded() (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("deferred: %w", err)
		}
	}()
	return f()
}

// deferred wrap with no guard is not a return of Errorf; out of scope.
func deferredUnguarded() (err error) {
	defer func() {
		err = fmt.Errorf("deferred: %w", err)
	}()
	return f()
}

func notReturned() {
	err := f()
	_ = fmt.Errorf("wrap: %w", err)
}

func nonErrorVerb(s string) error {
	return fmt.Errorf("bad %s", s)
}

func percentLiteral() error {
	err := f()
	if err != nil {
		return fmt.Errorf("100%% failed: %w", err)
	}
	return nil
}

func switchGuard() error {
	err := f()
	switch {
	case err != nil:
		return fmt.Errorf("wrap: %w", err)
	}
	return nil
}

func nilCheckThenNonNilCheck() error {
	err := f()
	flag := false
	if err == nil {
		flag = true
	}
	_ = flag
	if err != nil {
		return fmt.Errorf("wrap: %w", err)
	}
	return nil
}

func ctxDone(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("aborted: %w", ctx.Err())
	}
}
