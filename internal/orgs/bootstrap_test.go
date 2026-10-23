package orgs

import (
	"context"
	"crypto/rand"
	"os"
	"strings"
	"testing"

	"github.com/cavula/forge/internal/database"
	"github.com/cavula/forge/internal/testutil"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

func fixture(t *testing.T) BootstrapInput {
	t.Helper()
	id := func() string {
		var v pgtype.UUID
		if _, err := rand.Read(v.Bytes[:]); err != nil {
			t.Fatal("fixture randomness failed")
		}
		v.Bytes[6] = (v.Bytes[6] & 0x0f) | 0x40
		v.Bytes[8] = (v.Bytes[8] & 0x3f) | 0x80
		v.Valid = true
		return v.String()
	}
	return BootstrapInput{id(), "bootstrap test", id(), "https://issuer.test", "known-subject", "Known Admin"}
}

func TestBootstrapValidation(t *testing.T) {
	in := fixture(t)
	if !validBootstrap(in) {
		t.Fatal("valid operator configuration rejected")
	}
	for name, change := range map[string]func(*BootstrapInput){
		"uuid":           func(v *BootstrapInput) { v.OrgID = strings.ReplaceAll(v.OrgID, "-", "") },
		"uppercase uuid": func(v *BootstrapInput) { v.OrgID = "ABCDEF00-0000-0000-0000-000000000001" },
		"nil uuid":       func(v *BootstrapInput) { v.AdminID = "00000000-0000-0000-0000-000000000000" },
		"http":           func(v *BootstrapInput) { v.Issuer = "http://issuer.test" },
		"userinfo":       func(v *BootstrapInput) { v.Issuer = "https://secret@issuer.test" },
		"query":          func(v *BootstrapInput) { v.Issuer += "?secret=value" },
		"fragment":       func(v *BootstrapInput) { v.Issuer += "#fragment" },
		"empty fragment": func(v *BootstrapInput) { v.Issuer += "#" },
		"empty query":    func(v *BootstrapInput) { v.Issuer += "?" },
		"empty":          func(v *BootstrapInput) { v.Subject = "" },
		"long":           func(v *BootstrapInput) { v.Subject = strings.Repeat("s", 256) },
		"control":        func(v *BootstrapInput) { v.DisplayName = "admin\nsecret" },
		"whitespace":     func(v *BootstrapInput) { v.OrgName = " org" },
		"invalid utf8":   func(v *BootstrapInput) { v.DisplayName = string([]byte{0xff}) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := in
			change(&bad)
			if validBootstrap(bad) || Bootstrap(context.Background(), nil, bad) != ErrBootstrap {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	testutil.NoSecrets(t, ErrBootstrap.Error(), in.Issuer, in.Subject, in.DisplayName)
}

func TestBootstrapPostgres(t *testing.T) {
	ownerURL, runtimeURL := os.Getenv("TEST_BOOTSTRAP_OWNER_DATABASE_URL"), os.Getenv("TEST_DATABASE_URL")
	if ownerURL == "" || runtimeURL == "" {
		t.Skip("separate owner and runtime PostgreSQL URLs required")
	}
	ctx := context.Background()
	open := func(raw string) *pgxpool.Pool {
		t.Helper()
		config, err := pgxpool.ParseConfig(raw)
		if err != nil {
			t.Fatal("invalid PostgreSQL test configuration")
		}
		config.MaxConns = 1
		pool, err := pgxpool.NewWithConfig(ctx, config)
		if err != nil {
			t.Fatal("cannot open PostgreSQL test pool")
		}
		t.Cleanup(pool.Close)
		return pool
	}
	owner, runtime := open(ownerURL), open(runtimeURL)
	check := func(in BootstrapInput, want int) {
		t.Helper()
		err := database.WithOrg(ctx, runtime, in.OrgID, func(tx pgx.Tx) error {
			for _, sql := range []string{
				"SELECT count(*) FROM orgs WHERE id=$1",
				"SELECT count(*) FROM users WHERE org_id=$1",
				"SELECT count(*) FROM audit_events WHERE org_id=$1",
			} {
				var n int
				if err := tx.QueryRow(ctx, sql, in.OrgID).Scan(&n); err != nil {
					return err
				}
				if n != want {
					t.Fatal("bootstrap committed incomplete or unexpected records")
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal("cannot inspect bootstrap result")
		}
	}
	in := fixture(t)
	if Bootstrap(ctx, owner, in) != nil {
		t.Fatal("owner bootstrap failed")
	}
	check(in, 1)
	checkBinding := func() {
		t.Helper()
		err := database.WithOrg(ctx, runtime, in.OrgID, func(tx pgx.Tx) error {
			var matches bool
			err := tx.QueryRow(ctx, `SELECT u.issuer=$3 AND u.subject=$4 AND u.display_name=$5
 AND u.role='admin' AND a.action='organization.bootstrap'
 AND o.name=$6 AND a.actor_id=u.id FROM users u JOIN orgs o ON o.id=u.org_id
 JOIN audit_events a ON a.org_id=u.org_id WHERE u.org_id=$1 AND u.id=$2`,
				in.OrgID, in.AdminID, in.Issuer, in.Subject, in.DisplayName, in.OrgName).Scan(&matches)
			if err == nil && !matches {
				t.Fatal("operator binding or organization overwritten")
			}
			return err
		})
		if err != nil {
			t.Fatal("committed binding not readable")
		}
	}
	checkBinding()
	conflict := fixture(t)
	conflict.OrgID = in.OrgID
	if Bootstrap(ctx, owner, conflict) != ErrBootstrap {
		t.Fatal("duplicate organization accepted")
	}
	check(in, 1)
	checkBinding()
	unauthorized := fixture(t)
	if Bootstrap(ctx, runtime, unauthorized) != ErrBootstrap {
		t.Fatal("runtime credentials accepted for bootstrap")
	}
	check(unauthorized, 0)
	// Fail the final INSERT to prove prior organization/admin writes roll back.
	rollback := fixture(t)
	trigger := "bootstrap_failure_" + strings.ReplaceAll(rollback.OrgID, "-", "")
	if _, err := owner.Exec(ctx, `CREATE FUNCTION pg_temp.reject_bootstrap() RETURNS trigger
 LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected audit failure'; END $$`); err != nil {
		t.Fatal("cannot install rollback test function")
	}
	if _, err := owner.Exec(ctx, "CREATE TRIGGER "+trigger+" BEFORE INSERT ON public.audit_events FOR EACH ROW WHEN (NEW.org_id='"+rollback.OrgID+"'::uuid) EXECUTE FUNCTION pg_temp.reject_bootstrap()"); err != nil {
		t.Fatal("cannot install rollback test trigger")
	}
	defer func() {
		if _, err := owner.Exec(ctx, "DROP TRIGGER "+trigger+" ON public.audit_events"); err != nil {
			t.Error("cannot remove rollback test trigger")
		}
	}()
	if Bootstrap(ctx, owner, rollback) != ErrBootstrap {
		t.Fatal("failed audit insertion accepted")
	}
	check(rollback, 0)
	var leaked bool
	if err := owner.QueryRow(ctx, "SELECT nullif(current_setting('forge.org_id',true),'') IS NOT NULL").Scan(&leaked); err != nil || leaked {
		t.Fatal("operator tenant context leaked after transaction")
	}
	// Append-only audit fixtures are intentionally retained under random UUIDs.
}
