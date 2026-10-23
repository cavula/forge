// bootstrap is an explicit operator command; the server never invokes it.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/cavula/forge/internal/orgs"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	id, err := bootstrap(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, orgs.ErrBootstrap)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stdout, id)
}

func bootstrap(ctx context.Context) (string, error) {
	ownerURL := os.Getenv("FORGE_BOOTSTRAP_OWNER_URL")
	if len(os.Args) != 1 || ownerURL == "" {
		return "", orgs.ErrBootstrap
	}
	pool, err := pgxpool.New(ctx, ownerURL)
	if err != nil {
		return "", orgs.ErrBootstrap
	}
	defer pool.Close()
	in := orgs.BootstrapInput{
		OrgID: os.Getenv("FORGE_BOOTSTRAP_ORG_ID"), OrgName: os.Getenv("FORGE_BOOTSTRAP_ORG_NAME"),
		AdminID: os.Getenv("FORGE_BOOTSTRAP_ADMIN_ID"), DisplayName: os.Getenv("FORGE_BOOTSTRAP_ADMIN_NAME"),
		Issuer: os.Getenv("FORGE_BOOTSTRAP_OIDC_ISSUER"), Subject: os.Getenv("FORGE_BOOTSTRAP_OIDC_SUBJECT"),
	}
	if err := orgs.Bootstrap(ctx, pool, in); err != nil {
		return "", orgs.ErrBootstrap
	}
	return in.OrgID, nil
}
