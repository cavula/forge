package database

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

func stackSchemaFixture(t *testing.T) (context.Context, *pgxpool.Pool, *goose.Provider) {
	t.Helper()
	ownerURL, runtimeURL := os.Getenv("DATABASE_URL"), os.Getenv("TEST_DATABASE_URL")
	if ownerURL == "" || runtimeURL == "" {
		t.Skip("DATABASE_URL and TEST_DATABASE_URL required for disposable PostgreSQL schema test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	controller, err := pgxpool.New(ctx, ownerURL)
	if err != nil {
		t.Fatal("migration-owner connection failed")
	}
	t.Cleanup(controller.Close)
	var safe bool
	if err := controller.QueryRow(ctx, `SELECT NOT rolsuper AND NOT rolbypassrls AND rolcreatedb
 FROM pg_roles WHERE rolname=current_user`).Scan(&safe); err != nil {
		var databaseError *pgconn.PgError
		if errors.As(err, &databaseError) {
			t.Fatalf("migration-owner role query failed (SQLSTATE %s)", databaseError.Code)
		}
		t.Fatalf("migration-owner role query failed (%T)", err)
	}
	if !safe {
		t.Fatal("non-superuser NOBYPASSRLS migration owner with CREATEDB required")
	}
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	name := pgx.Identifier{"forge_stack_schema_" + hex.EncodeToString(random[:])}
	if _, err := controller.Exec(ctx, "CREATE DATABASE "+name.Sanitize()); err != nil {
		t.Fatal("disposable database creation failed")
	}
	t.Cleanup(func() {
		if _, err := controller.Exec(ctx, "DROP DATABASE "+name.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Error("disposable database removal failed")
		}
	})
	owner, err := pgx.ParseConfig(ownerURL)
	if err != nil {
		t.Fatal("invalid migration-owner configuration")
	}
	owner.Database = name[0]
	db := stdlib.OpenDB(*owner)
	t.Cleanup(func() { _ = db.Close() })
	migrations, err := fs.Sub(Migrations, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.UpTo(ctx, 5); err != nil {
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(runtimeURL)
	if err != nil {
		t.Fatal("invalid runtime configuration")
	}
	config.ConnConfig.Database, config.MaxConns = name[0], 1
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal("runtime connection failed")
	}
	t.Cleanup(pool.Close)
	if err := pool.QueryRow(ctx, `SELECT NOT rolsuper AND NOT rolbypassrls
 AND c.relrowsecurity AND c.relforcerowsecurity AND c.relowner<>r.oid
 FROM pg_roles r CROSS JOIN pg_class c WHERE r.rolname=current_user AND c.oid='stacks'::regclass`).Scan(&safe); err != nil || !safe {
		t.Fatal("distinct nonowner NOBYPASSRLS runtime and stack FORCE RLS required")
	}
	return ctx, pool, provider
}

func TestStackStorageSchema(t *testing.T) {
	ctx, pool, provider := stackSchemaFixture(t)
	orgA, orgB := "60000000-0000-0000-0000-000000000001", "60000000-0000-0000-0000-000000000002"
	exec := func(org, query string, args ...any) error {
		return WithOrg(ctx, pool, org, func(tx pgx.Tx) error { _, err := tx.Exec(ctx, query, args...); return err })
	}
	truth := func(org, query string, args ...any) {
		t.Helper()
		if err := WithOrg(ctx, pool, org, func(tx pgx.Tx) error {
			var ok bool
			if err := tx.QueryRow(ctx, query, args...).Scan(&ok); err != nil {
				return err
			}
			if !ok {
				t.Fatal("schema assertion failed")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, org := range []string{orgA, orgB} {
		for _, query := range []string{
			"INSERT INTO orgs(id,name) VALUES($1,'schema fixture')",
			"INSERT INTO stacks(org_id,id,name) VALUES($1,$1,$2)",
			"INSERT INTO runs(org_id,id,stack_id,status) VALUES($1,$1,$1,'FINISHED')",
			"INSERT INTO state_versions(org_id,id,stack_id,serial,ciphertext,wrapped_dek,nonce,key_id) VALUES($1,$1,$1,0,'cipher','wrapped','123456789012','key')",
			"INSERT INTO audit_events(org_id,id,stack_id,action) VALUES($1,$1,$1,'fixture.created')",
		} {
			args := []any{org}
			if strings.HasPrefix(query, "INSERT INTO stacks") {
				name := "legacy"
				if org == orgB {
					name = strings.Repeat("l", 101)
				}
				args = append(args, name)
			}
			if err := exec(org, query, args...); err != nil {
				t.Fatal(err)
			}
		}
	}
	legacy := func() {
		for _, org := range []string{orgA, orgB} {
			truth(org, `SELECT repository_url IS NULL AND branch IS NULL AND working_directory IS NULL
 AND engine_version IS NULL AND environment_variables IS NULL AND created_at IS NULL
 AND deleted_at IS NULL AND configuration_revision=1 FROM stacks WHERE org_id=$1 AND id=$1`, org)
		}
		truth(orgB, "SELECT octet_length(name)=101 AND engine='opentofu' FROM stacks WHERE org_id=$1 AND id=$1", orgB)
	}
	if _, err := provider.UpTo(ctx, 6); err != nil {
		t.Fatal(err)
	}
	legacy()
	truth(orgA, "SELECT NOT has_table_privilege(current_user,'stacks','DELETE')")
	if _, err := provider.DownTo(ctx, 5); err != nil {
		t.Fatal(err)
	}
	truth(orgA, "SELECT has_table_privilege(current_user,'stacks','DELETE')")
	if _, err := provider.UpTo(ctx, 6); err != nil {
		t.Fatal(err)
	}
	legacy()
	requireSQLState(t, exec(orgA, "UPDATE stacks SET repository_url='https://example.test/org/repo' WHERE org_id=$1 AND id=$1", orgA), "23514")
	if err := exec(orgA, `UPDATE stacks SET repository_url='https://example.test/org/repo',branch='main',
 working_directory='.',engine_version='1.10.0',environment_variables='[]',configuration_revision=2
 WHERE org_id=$1 AND id=$1`, orgA); err != nil {
		t.Fatal(err)
	}
	truth(orgA, "SELECT created_at IS NULL AND environment_variables='[]'::jsonb AND configuration_revision=2 FROM stacks WHERE org_id=$1 AND id=$1", orgA)
	for _, assignment := range []string{"configuration_revision=0", "configuration_revision=-1", "repository_url=NULL",
		"repository_url=''", "branch=repeat('x',256)", "working_directory=repeat('x',513)", "engine_version=repeat('x',65)",
		"environment_variables='{}'", "environment_variables=(SELECT jsonb_agg(n) FROM generate_series(1,65) n)",
		"environment_variables=jsonb_build_array(repeat('x',65536))", "engine='unknown'"} {
		requireSQLState(t, exec(orgA, "UPDATE stacks SET "+assignment+" WHERE org_id=$1 AND id=$1", orgA), "23514")
	}
	if err := WithOrg(ctx, pool, orgA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO stacks(org_id,id,name,repository_url,branch,working_directory,engine_version,environment_variables)
 VALUES($1,'70000000-0000-0000-0000-000000000001','new','https://example.test/org/repo','main','.','1.10.0','[]')`, orgA)
		if err != nil {
			return err
		}
		var actual bool
		err = tx.QueryRow(ctx, "SELECT created_at=now() AND configuration_revision=1 FROM stacks WHERE org_id=$1 AND name='new'", orgA).Scan(&actual)
		if err == nil && !actual {
			t.Fatal("new creation timestamp/revision default incorrect")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := exec(orgA, "UPDATE stacks SET deleted_at=now(),configuration_revision=3 WHERE org_id=$1 AND id=$1", orgA); err != nil {
		t.Fatal(err)
	}
	requireSQLState(t, exec(orgA, "INSERT INTO stacks(org_id,id,name) VALUES($1,'70000000-0000-0000-0000-000000000002','legacy')", orgA), "23505")
	requireSQLState(t, exec(orgA, "DELETE FROM stacks WHERE org_id=$1 AND id=$1", orgA), "42501")
	for _, table := range []string{"runs", "state_versions", "audit_events"} {
		truth(orgA, "SELECT count(*)=1 FROM "+table+" WHERE org_id=$1 AND stack_id=$1", orgA)
	}
	requireSQLState(t, exec(orgA, "INSERT INTO runs(org_id,id,stack_id) VALUES($1,'70000000-0000-0000-0000-000000000004',$2)", orgA, orgB), "23503")
	for _, pair := range [][2]string{{orgA, orgB}, {orgB, orgA}} {
		truth(pair[0], "SELECT count(*)=0 FROM stacks WHERE org_id=$1", pair[1])
		if err := WithOrg(ctx, pool, pair[0], func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, "UPDATE stacks SET configuration_revision=configuration_revision+1 WHERE org_id=$1", pair[1])
			if err == nil && tag.RowsAffected() != 0 {
				t.Fatal("cross-tenant update succeeded")
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		requireSQLState(t, exec(pair[0], "INSERT INTO stacks(org_id,id,name) VALUES($1,'70000000-0000-0000-0000-000000000003','foreign')", pair[1]), "42501")
	}
	var reset bool
	if err := pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM stacks)=0 AND coalesce(current_setting('forge.org_id',true),'')=''").Scan(&reset); err != nil || !reset {
		t.Fatal("pooled tenant context leaked")
	}
	_, err := pool.Exec(ctx, "INSERT INTO stacks(org_id,id,name) VALUES($1,'70000000-0000-0000-0000-000000000003','missing')", orgA)
	requireSQLState(t, err, "42501")
	_, err = provider.DownTo(ctx, 5)
	requireSQLState(t, err, "23514")
	if version, err := provider.GetDBVersion(ctx); err != nil || version != 6 {
		t.Fatal("unsafe downgrade changed migration version")
	}
	truth(orgA, "SELECT deleted_at IS NOT NULL AND configuration_revision=3 FROM stacks WHERE org_id=$1 AND id=$1", orgA)
	truth(orgA, "SELECT count(*)=0 FROM pg_constraint WHERE conrelid='stacks'::regclass AND conname='stacks_downgrade_safe'")
	truth(orgA, "SELECT NOT has_table_privilege(current_user,'stacks','DELETE')")
}
