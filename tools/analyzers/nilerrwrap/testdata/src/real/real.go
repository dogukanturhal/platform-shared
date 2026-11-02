// SPDX-License-Identifier: Apache-2.0

// Cases lifted from platform-core commits 83ddc62 and dbb6ed8 (pre-fix shapes).
package real

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
)

type cost struct{}

type repo struct{ db *sql.DB }

type cache struct{}

func (c *cache) set(string) error { return nil }

// custom-fields RedisCache.Set before dbb6ed8.
func (c *cache) Set(key string) error {
	err := c.set(key)
	if err != nil {
		log.Println("Redis SET failed", err)
	}
	return fmt.Errorf("Set: %w", err) // want `may be nil`
}

// master-data CustomerRepository.UpdateCreditExposure before 83ddc62.
func (r *repo) UpdateCreditExposure(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, "update")
	return fmt.Errorf("UpdateCreditExposure: %w", err) // want `may be nil`
}

// master-data CostCenterRepository.GetByID before 83ddc62.
func (r *repo) GetByID(ctx context.Context) (*cost, error) {
	cc := &cost{}
	err := r.db.QueryRowContext(ctx, "select").Scan(cc)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return cc, fmt.Errorf("GetByID: %w", err) // want `may be nil`
}

// Post-fix shapes must stay clean.
func (c *cache) SetFixed(key string) error {
	err := c.set(key)
	if err != nil {
		log.Println("Redis SET failed", err)
		return fmt.Errorf("Set: %w", err)
	}
	return nil
}

func (r *repo) GetByIDFixed(ctx context.Context) (*cost, error) {
	cc := &cost{}
	err := r.db.QueryRowContext(ctx, "select").Scan(cc)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetByID: %w", err)
	}
	return cc, nil
}
