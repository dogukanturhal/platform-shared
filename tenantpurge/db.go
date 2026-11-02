// SPDX-License-Identifier: Apache-2.0

package tenantpurge

import (
	"context"
	"database/sql"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Rows is the subset of row iteration the sweep needs.
type Rows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
	Close()
}

// Tx is one database transaction.
type Tx interface {
	// Exec runs a statement and returns the rows affected.
	Exec(ctx context.Context, query string, args ...any) (int64, error)
	Query(ctx context.Context, query string, args ...any) (Rows, error)
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// DB opens transactions. Adapters exist for database/sql and pgxpool.
type DB interface {
	Begin(ctx context.Context) (Tx, error)
}

// NewSQLDB adapts a *sql.DB (lib/pq, pgx stdlib).
func NewSQLDB(db *sql.DB) DB { return sqlDB{db} }

type sqlDB struct{ db *sql.DB }

func (d sqlDB) Begin(ctx context.Context) (Tx, error) {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	return sqlTx{tx}, nil
}

type sqlTx struct{ tx *sql.Tx }

func (t sqlTx) Exec(ctx context.Context, q string, args ...any) (int64, error) {
	res, err := t.tx.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (t sqlTx) Query(ctx context.Context, q string, args ...any) (Rows, error) {
	r, err := t.tx.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	return sqlRows{r}, nil
}

func (t sqlTx) Commit(context.Context) error   { return t.tx.Commit() }
func (t sqlTx) Rollback(context.Context) error { return t.tx.Rollback() }

type sqlRows struct{ r *sql.Rows }

func (r sqlRows) Next() bool             { return r.r.Next() }
func (r sqlRows) Scan(dest ...any) error { return r.r.Scan(dest...) }
func (r sqlRows) Err() error             { return r.r.Err() }
func (r sqlRows) Close()                 { _ = r.r.Close() }

// NewPgxDB adapts a pgxpool.Pool.
func NewPgxDB(pool *pgxpool.Pool) DB { return pgxDB{pool} }

type pgxDB struct{ pool *pgxpool.Pool }

func (d pgxDB) Begin(ctx context.Context) (Tx, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return pgxTx{tx}, nil
}

type pgxTx struct{ tx pgx.Tx }

func (t pgxTx) Exec(ctx context.Context, q string, args ...any) (int64, error) {
	tag, err := t.tx.Exec(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (t pgxTx) Query(ctx context.Context, q string, args ...any) (Rows, error) {
	return t.tx.Query(ctx, q, args...)
}

func (t pgxTx) Commit(ctx context.Context) error   { return t.tx.Commit(ctx) }
func (t pgxTx) Rollback(ctx context.Context) error { return t.tx.Rollback(ctx) }
