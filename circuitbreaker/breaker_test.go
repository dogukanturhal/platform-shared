// SPDX-License-Identifier: Apache-2.0

package circuitbreaker_test

import (
	"errors"
	"testing"
	"time"

	"github.com/dogukanturhal/platform-shared/circuitbreaker"
	"github.com/sony/gobreaker/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewBreaker_DefaultSettings(t *testing.T) {
	b := circuitbreaker.NewBreaker("test-defaults")
	require.NotNil(t, b)
	assert.Equal(t, gobreaker.StateClosed, b.State())
	assert.Equal(t, "test-defaults", b.Name())
}

func TestBreaker_TripsAfterConsecutiveFailures(t *testing.T) {
	b := circuitbreaker.NewBreaker("test-trip",
		circuitbreaker.WithTimeout(100*time.Millisecond),
	)

	errFail := errors.New("intentional failure")
	for i := 0; i < 5; i++ {
		_, err := b.Execute(func() (any, error) {
			return nil, errFail
		})
		require.Error(t, err)
	}

	// After 5 consecutive failures the breaker must be open.
	assert.Equal(t, gobreaker.StateOpen, b.State())
}

func TestBreaker_OpenStateFastFails(t *testing.T) {
	b := circuitbreaker.NewBreaker("test-open",
		circuitbreaker.WithTimeout(100*time.Millisecond),
	)

	errFail := errors.New("fail")
	for i := 0; i < 5; i++ {
		b.Execute(func() (any, error) { return nil, errFail }) //nolint:errcheck,gosec // test helper
	}
	require.Equal(t, gobreaker.StateOpen, b.State())

	_, err := b.Execute(func() (any, error) { return "should not run", nil })
	assert.ErrorIs(t, err, gobreaker.ErrOpenState)
}

func TestBreaker_RecoverAfterTimeout(t *testing.T) {
	b := circuitbreaker.NewBreaker("test-recover",
		circuitbreaker.WithTimeout(50*time.Millisecond),
		circuitbreaker.WithMaxRequests(1),
	)

	errFail := errors.New("fail")
	for i := 0; i < 5; i++ {
		b.Execute(func() (any, error) { return nil, errFail }) //nolint:errcheck,gosec // test helper
	}
	require.Equal(t, gobreaker.StateOpen, b.State())

	// Wait for timeout to elapse so the breaker moves to half-open.
	time.Sleep(60 * time.Millisecond)

	// A successful probe in half-open should close the breaker.
	_, err := b.Execute(func() (any, error) { return "ok", nil })
	require.NoError(t, err)
	assert.Equal(t, gobreaker.StateClosed, b.State())
}

func TestBreaker_StateToString(t *testing.T) {
	assert.Equal(t, "closed", circuitbreaker.StateToString(gobreaker.StateClosed))
	assert.Equal(t, "half-open", circuitbreaker.StateToString(gobreaker.StateHalfOpen))
	assert.Equal(t, "open", circuitbreaker.StateToString(gobreaker.StateOpen))
}

func TestBreaker_CountsReflectRequests(t *testing.T) {
	b := circuitbreaker.NewBreaker("test-counts",
		circuitbreaker.WithInterval(0), // never reset counts automatically
	)

	b.Execute(func() (any, error) { return "ok", nil })              //nolint:errcheck,gosec // test helper
	b.Execute(func() (any, error) { return nil, errors.New("bad") }) //nolint:errcheck,gosec // test helper

	counts := b.Counts()
	assert.Equal(t, uint32(2), counts.Requests)
	assert.Equal(t, uint32(1), counts.TotalSuccesses)
	assert.Equal(t, uint32(1), counts.TotalFailures)
}

func TestRegistry_GetOrCreateReturnsSameInstance(t *testing.T) {
	reg := circuitbreaker.NewRegistry()

	b1 := reg.MustGetOrCreate("svc-a")
	b2 := reg.MustGetOrCreate("svc-a")
	assert.Same(t, b1, b2, "GetOrCreate must return the same *Breaker for the same name")
}

func TestRegistry_GetExistingBreaker(t *testing.T) {
	reg := circuitbreaker.NewRegistry()

	created := reg.MustGetOrCreate("svc-b")
	got, ok := reg.Get("svc-b")
	require.True(t, ok)
	assert.Same(t, created, got)
}

func TestRegistry_GetMissingBreaker(t *testing.T) {
	reg := circuitbreaker.NewRegistry()
	_, ok := reg.Get("does-not-exist")
	assert.False(t, ok)
}

func TestRegistry_ListAll(t *testing.T) {
	reg := circuitbreaker.NewRegistry()
	reg.MustGetOrCreate("alpha")
	reg.MustGetOrCreate("beta")

	all := reg.ListAll()
	assert.Len(t, all, 2)
	_, hasAlpha := all["alpha"]
	_, hasBeta := all["beta"]
	assert.True(t, hasAlpha)
	assert.True(t, hasBeta)

	for _, status := range all {
		assert.Equal(t, "closed", status.State)
		assert.NotEmpty(t, status.Name)
	}
}

func TestRegistry_GetOrCreate_DifferentNamesAreDifferentBreakers(t *testing.T) {
	reg := circuitbreaker.NewRegistry()
	b1 := reg.MustGetOrCreate("x")
	b2 := reg.MustGetOrCreate("y")
	assert.NotSame(t, b1, b2)
}

func TestRegistry_RejectsWhenFull(t *testing.T) {
	reg := circuitbreaker.NewRegistry(circuitbreaker.WithMaxSize(2))
	reg.MustGetOrCreate("a")
	reg.MustGetOrCreate("b")

	_, err := reg.GetOrCreate("c")
	assert.ErrorIs(t, err, circuitbreaker.ErrRegistryFull)

	// Existing breakers should still be accessible.
	existing, err := reg.GetOrCreate("a")
	require.NoError(t, err)
	assert.Equal(t, "a", existing.Name())
	assert.Equal(t, 2, reg.Len())
}

func TestBreaker_SanitizesName(t *testing.T) {
	b := circuitbreaker.NewBreaker("workflow engine → iam service")
	// Spaces and → should be replaced with _
	assert.NotContains(t, b.Name(), " ")
	assert.NotContains(t, b.Name(), "→")
}
