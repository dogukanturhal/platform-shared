// SPDX-License-Identifier: Apache-2.0

package tenantpurge

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/dogukanturhal/platform-shared/config"
)

// Retain declares rows the service keeps after an erase, with the legal basis.
// Rows of Table that mention the tenant and satisfy Where are neither deleted nor
// counted as residue; an empty Where keeps every such row. Where is trusted SQL
// written by the service, never user input.
type Retain struct {
	Schema string // default "public"
	Table  string
	Where  string
	Basis  string
}

func (r Retain) ref() TableRef {
	s := r.Schema
	if s == "" {
		s = "public"
	}
	return TableRef{Schema: s, Name: r.Table}
}

// keepExpr is the SQL expression that is true for retained rows.
func (r Retain) keepExpr() string {
	if strings.TrimSpace(r.Where) == "" {
		return "true"
	}
	return "COALESCE((" + r.Where + "), false)"
}

// Config configures a Participant.
type Config struct {
	// Service is the name reported in acks, e.g. "billing".
	Service string
	DB      DB
	// Schemas are the service's own schemas; default {"public"}.
	Schemas []string
	// ExtraTenantColumns are column names (besides tenant_id and *_tenant_id)
	// that reference a tenant.
	ExtraTenantColumns []string
	Retain             []Retain
	Hooks              Hooks
	// StatementTimeout bounds each statement of a run; default 10 minutes.
	StatementTimeout time.Duration
	Logger           *zap.Logger

	// Kafka (used by Run only).
	Brokers []string
	SASL    config.KafkaSASLConfig
	// GroupID must be unique per service (every participant sees every command);
	// default "<Service>-tenant-purge".
	GroupID      string
	CommandTopic string // default DefaultCommandTopic
	AckTopic     string // default DefaultAckTopic
}

// Participant handles purge commands for one service.
type Participant struct {
	cfg    Config
	extra  map[string]struct{}
	retain map[TableRef]Retain
	log    *zap.Logger
}

// New validates cfg and returns a Participant.
func New(cfg Config) (*Participant, error) {
	if cfg.Service == "" {
		return nil, errors.New("tenantpurge: Config.Service is required")
	}
	if cfg.DB == nil {
		return nil, errors.New("tenantpurge: Config.DB is required")
	}
	if len(cfg.Schemas) == 0 {
		cfg.Schemas = []string{"public"}
	}
	if cfg.Hooks == nil {
		cfg.Hooks = NopHooks{}
	}
	if cfg.StatementTimeout <= 0 {
		cfg.StatementTimeout = 10 * time.Minute
	}
	if cfg.Logger == nil {
		cfg.Logger = zap.NewNop()
	}
	if cfg.GroupID == "" {
		cfg.GroupID = cfg.Service + "-tenant-purge"
	}
	if cfg.CommandTopic == "" {
		cfg.CommandTopic = DefaultCommandTopic
	}
	if cfg.AckTopic == "" {
		cfg.AckTopic = DefaultAckTopic
	}
	p := &Participant{
		cfg:    cfg,
		extra:  make(map[string]struct{}, len(cfg.ExtraTenantColumns)),
		retain: make(map[TableRef]Retain, len(cfg.Retain)),
		log:    cfg.Logger.With(zap.String("component", "tenantpurge"), zap.String("service", cfg.Service)),
	}
	for _, c := range cfg.ExtraTenantColumns {
		p.extra[strings.ToLower(c)] = struct{}{}
	}
	for _, r := range cfg.Retain {
		if r.Table == "" || strings.TrimSpace(r.Basis) == "" {
			return nil, fmt.Errorf("tenantpurge: Retain needs Table and Basis (got %q)", r.Table)
		}
		p.retain[r.ref()] = r
	}
	return p, nil
}

// Handle runs one command and returns the ack to publish. It never panics and
// never returns before the protected-id check.
func (p *Participant) Handle(ctx context.Context, cmd Command) (ack Ack) {
	defer func() {
		if r := recover(); r != nil {
			ack = BuildAck(cmd, p.cfg.Service, PhaseResult{Err: fmt.Errorf("panic: %v", r)})
		}
	}()
	id, err := CheckTenantID(cmd.TenantID)
	if err != nil {
		var st error = errors.New("invalid tenant id")
		if errors.Is(err, ErrProtectedTenant) {
			st = Blocked("protected tenant id")
		}
		p.log.Warn("purge command refused", zap.String("run_id", cmd.RunID), zap.String("phase", string(cmd.Phase)), zap.Error(err))
		return BuildAck(cmd, p.cfg.Service, PhaseResult{Err: st})
	}
	cmd.TenantID = id

	var res PhaseResult
	switch cmd.Phase {
	case PhasePlan:
		res = p.plan(ctx, cmd)
	case PhaseQuiesce:
		ext, err := p.cfg.Hooks.Quiesce(ctx, cmd)
		res = PhaseResult{External: ext, Err: err}
	case PhaseErase:
		res = p.erase(ctx, cmd)
	default:
		res = PhaseResult{Err: fmt.Errorf("unsupported phase %q", cmd.Phase)}
	}
	ack = BuildAck(cmd, p.cfg.Service, res)
	p.log.Info("purge phase done",
		zap.String("run_id", cmd.RunID), zap.String("tenant_id", cmd.TenantID),
		zap.String("phase", string(cmd.Phase)), zap.Int("attempt", cmd.Attempt),
		zap.String("status", string(ack.Status)))
	return ack
}

// begin opens a transaction scoped to the tenant. In purge mode it also sets the
// immutability-trigger bypass and defers constraints. set_config(..., true) is the
// parameterisable form of SET LOCAL.
func (p *Participant) begin(ctx context.Context, tenantID string, purge bool) (Tx, error) {
	tx, err := p.cfg.DB.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	stmts := [][]any{
		{"SELECT set_config('statement_timeout', $1, true)", fmt.Sprintf("%d", p.cfg.StatementTimeout.Milliseconds())},
		{"SELECT set_config('app.current_tenant_id', $1, true)", tenantID},
	}
	if purge {
		stmts = append(stmts, []any{"SELECT set_config('app.tenant_purge', $1, true)", "on"})
	}
	for _, s := range stmts {
		if _, err := tx.Exec(ctx, s[0].(string), s[1:]...); err != nil {
			_ = tx.Rollback(ctx)
			return nil, fmt.Errorf("set session scope: %w", err)
		}
	}
	if purge {
		if _, err := tx.Exec(ctx, "SET CONSTRAINTS ALL DEFERRED"); err != nil {
			_ = tx.Rollback(ctx)
			return nil, fmt.Errorf("defer constraints: %w", err)
		}
	}
	return tx, nil
}

// loadSet reads the catalog and checks the Retain declarations against it.
func (p *Participant) loadSet(ctx context.Context, tx Tx) (*sweepSet, error) {
	set, err := buildSweepSet(ctx, tx, p.cfg.Schemas, p.extra)
	if err != nil {
		return nil, err
	}
	for ref := range p.retain {
		t, ok := set.all[ref]
		if !ok {
			return nil, fmt.Errorf("tenantpurge: Retain table %s not found in schemas", ref)
		}
		if valuePredicate(t.Columns) == "" {
			return nil, fmt.Errorf("tenantpurge: Retain table %s has no uuid/text/json column to match", ref)
		}
	}
	if len(set.cyclic) > 0 {
		p.log.Warn("foreign key cycle among tenant tables, deleting with deferred constraints", zap.Any("tables", set.cyclic))
	}
	return set, nil
}

func countRows(ctx context.Context, tx Tx, q, tenantID string) (int64, error) {
	rows, err := tx.Query(ctx, q, tenantID)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var n int64
	if rows.Next() {
		if err := rows.Scan(&n); err != nil {
			return 0, err
		}
	}
	return n, rows.Err()
}

// retainedRows counts rows kept by the declared Retain specs for the tenant.
func (p *Participant) retainedRows(ctx context.Context, tx Tx, set *sweepSet, tenantID string) ([]RetainedRows, error) {
	var out []RetainedRows
	for ref, r := range p.retain {
		pred := valuePredicate(set.all[ref].Columns)
		n, err := countRows(ctx, tx, "SELECT count(*) FROM "+ref.quoted()+" WHERE "+pred+" AND "+r.keepExpr(), tenantID)
		if err != nil {
			return nil, fmt.Errorf("count retained %s: %w", ref, err)
		}
		if n > 0 {
			out = append(out, RetainedRows{Table: ref.String(), N: n, Basis: r.Basis})
		}
	}
	return out, nil
}

// plan is the dry run: per-table counts of what erase would delete, retained
// rows, and what the service hooks report.
func (p *Participant) plan(ctx context.Context, cmd Command) PhaseResult {
	rep, err := p.cfg.Hooks.Plan(ctx, cmd)
	if err != nil {
		return PhaseResult{Err: err}
	}
	tx, err := p.begin(ctx, cmd.TenantID, false)
	if err != nil {
		return PhaseResult{Err: err}
	}
	defer func() { _ = tx.Rollback(ctx) }()
	set, err := p.loadSet(ctx, tx)
	if err != nil {
		return PhaseResult{Err: err}
	}
	counts := make(map[string]int64, len(set.ordered))
	for _, t := range set.ordered {
		n, err := countRows(ctx, tx, "SELECT count(*) FROM "+t.Ref.quoted()+" WHERE "+tenantPredicate(t.TenantColumns(p.extra))+p.notRetained(t.Ref), cmd.TenantID)
		if err != nil {
			return PhaseResult{Err: fmt.Errorf("count %s: %w", t.Ref, err)}
		}
		counts[t.Ref.String()] = n
	}
	retained, err := p.retainedRows(ctx, tx, set, cmd.TenantID)
	if err != nil {
		return PhaseResult{Err: err}
	}
	res := PhaseResult{Counts: counts, Retained: retained, External: rep.External}
	if len(rep.Blockers) > 0 {
		res.Err = Blocked(strings.Join(rep.Blockers, "; "))
	}
	return res
}

// notRetained returns " AND NOT <keep>" for a retained table, else "".
func (p *Participant) notRetained(ref TableRef) string {
	if r, ok := p.retain[ref]; ok {
		return " AND NOT " + r.keepExpr()
	}
	return ""
}

// erase deletes the tenant's data: hooks first (they may need the rows), then one
// transaction with the catalog sweep and the value sweep, then post hooks.
func (p *Participant) erase(ctx context.Context, cmd Command) PhaseResult {
	// Validate the catalog and Retain declarations before any irreversible
	// external effect.
	if err := p.validate(ctx, cmd.TenantID); err != nil {
		return PhaseResult{Err: err}
	}

	var external []ExternalEffect
	pre, err := p.cfg.Hooks.BeforeErase(ctx, cmd)
	external = append(external, pre...)
	if err != nil {
		return PhaseResult{External: external, Err: err}
	}
	for _, e := range pre {
		if e.Outcome == OutcomeFailed {
			return PhaseResult{External: external} // BuildAck marks it failed; keep the rows for the retry
		}
	}

	counts, retained, err := p.eraseTx(ctx, cmd)
	if err != nil {
		return PhaseResult{Counts: counts, External: external, Err: err}
	}

	post, err := p.cfg.Hooks.AfterErase(ctx, cmd)
	external = append(external, post...)
	return PhaseResult{Counts: counts, Retained: retained, External: external, Err: err}
}

func (p *Participant) validate(ctx context.Context, tenantID string) error {
	tx, err := p.begin(ctx, tenantID, false)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = p.loadSet(ctx, tx)
	return err
}

func (p *Participant) eraseTx(ctx context.Context, cmd Command) (map[string]int64, []RetainedRows, error) {
	tx, err := p.begin(ctx, cmd.TenantID, true)
	if err != nil {
		return nil, nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	set, err := p.loadSet(ctx, tx)
	if err != nil {
		return nil, nil, err
	}
	if err := p.cfg.Hooks.EraseTx(ctx, cmd, tx); err != nil {
		return nil, nil, err
	}
	counts := make(map[string]int64, len(set.ordered))
	for _, t := range set.ordered {
		n, err := tx.Exec(ctx, "DELETE FROM "+t.Ref.quoted()+" WHERE "+tenantPredicate(t.TenantColumns(p.extra))+p.notRetained(t.Ref), cmd.TenantID)
		if err != nil {
			return nil, nil, fmt.Errorf("delete %s: %w", t.Ref, err)
		}
		counts[t.Ref.String()] = n
	}
	if res, err := p.residue(ctx, tx, set, cmd.TenantID); err != nil {
		return nil, nil, err
	} else if len(res) > 0 {
		return counts, nil, fmt.Errorf("residue after erase, rolled back: %s", formatResidue(res))
	}
	retained, err := p.retainedRows(ctx, tx, set, cmd.TenantID)
	if err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, fmt.Errorf("commit: %w", err)
	}
	committed = true
	return counts, retained, nil
}

// residue is the value sweep: it looks for the tenant id in every uuid, text and
// json column of every base table of the schemas, ignoring declared Retain rows.
// Counts are capped at 1000 per table.
func (p *Participant) residue(ctx context.Context, tx Tx, set *sweepSet, tenantID string) (map[string]int64, error) {
	refs := make([]TableRef, 0, len(set.all))
	for ref := range set.all {
		refs = append(refs, ref)
	}
	sortRefs(refs)
	out := make(map[string]int64)
	for _, ref := range refs {
		pred := valuePredicate(set.all[ref].Columns)
		if pred == "" {
			continue
		}
		q := "SELECT count(*) FROM (SELECT 1 FROM " + ref.quoted() + " WHERE " + pred + p.notRetained(ref) + " LIMIT 1000) s"
		n, err := countRows(ctx, tx, q, tenantID)
		if err != nil {
			return nil, fmt.Errorf("value sweep %s: %w", ref, err)
		}
		if n > 0 {
			out[ref.String()] = n
		}
	}
	return out, nil
}

func formatResidue(res map[string]int64) string {
	keys := make([]string, 0, len(res))
	for k := range res {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s=%d", k, res[k])
	}
	return strings.Join(parts, ",")
}
