// Package orgs manages organization membership.
package orgs

import (
	"context"
	"crypto/rand"
	"errors"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cavula/forge/internal/database"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrBootstrap deliberately omits identities, credentials and database details.
var ErrBootstrap = errors.New("organization bootstrap failed")

// BootstrapInput is trusted operator configuration, never HTTP/request input.
// The issuer and subject must identify a known principal at the configured IdP.
type BootstrapInput struct {
	OrgID, OrgName, AdminID, Issuer, Subject, DisplayName string
}

// Bootstrap creates a new organization, initial admin and audit event atomically.
// Call only from the dedicated operator command with separately supplied owner
// credentials. Existing organizations are never updated or enrolled into.
func Bootstrap(ctx context.Context, pool *pgxpool.Pool, in BootstrapInput) error {
	if pool == nil || !validBootstrap(in) {
		return ErrBootstrap
	}
	var event pgtype.UUID
	if _, err := rand.Read(event.Bytes[:]); err != nil {
		return ErrBootstrap
	}
	event.Bytes[6] = (event.Bytes[6] & 0x0f) | 0x40
	event.Bytes[8] = (event.Bytes[8] & 0x3f) | 0x80
	event.Valid = true
	err := database.WithOrg(ctx, pool, in.OrgID, func(tx pgx.Tx) error {
		// Ownership is checked on this same transaction/connection. No SET ROLE,
		// BYPASSRLS or row_security override is used to adopt operator authority.
		var owner bool
		if err := tx.QueryRow(ctx, `SELECT current_user=session_user
 AND current_user <> 'forge_app' AND NOT r.rolsuper AND NOT r.rolbypassrls
 AND (SELECT count(*)=3 AND bool_and(c.relowner=r.oid
 AND c.relrowsecurity AND c.relforcerowsecurity) FROM pg_class c
 WHERE c.oid IN ('public.orgs'::regclass,'public.users'::regclass,
 'public.audit_events'::regclass)) FROM pg_roles r WHERE r.rolname=current_user`).Scan(&owner); err != nil || !owner {
			return ErrBootstrap
		}
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{"INSERT INTO public.orgs(id,name) VALUES($1,$2)", []any{in.OrgID, in.OrgName}},
			{`INSERT INTO public.users(org_id,id,issuer,subject,display_name,role)
 VALUES($1,$2,$3,$4,$5,'admin')`, []any{in.OrgID, in.AdminID, in.Issuer, in.Subject, in.DisplayName}},
			{`INSERT INTO public.audit_events(org_id,id,actor_id,action)
 VALUES($1,$2,$3,'organization.bootstrap')`, []any{in.OrgID, event.String(), in.AdminID}},
		} {
			if _, err := tx.Exec(ctx, q.sql, q.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return ErrBootstrap
	}
	return nil
}

func validBootstrap(in BootstrapInput) bool {
	for _, raw := range []string{in.OrgID, in.AdminID} {
		var id pgtype.UUID
		if id.Scan(raw) != nil || !id.Valid || id.String() != raw || id.Bytes == [16]byte{} {
			return false
		}
	}
	u, err := url.Parse(in.Issuer)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil &&
		u.RawQuery == "" && !u.ForceQuery && !strings.Contains(in.Issuer, "#") && cleanText(in.Issuer, 2048) &&
		cleanText(in.OrgName, 200) && cleanText(in.DisplayName, 200) && cleanText(in.Subject, 255)
}

func cleanText(s string, limit int) bool {
	return s != "" && len(s) <= limit && utf8.ValidString(s) && strings.TrimSpace(s) == s &&
		strings.IndexFunc(s, unicode.IsControl) == -1
}
