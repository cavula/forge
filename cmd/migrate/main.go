package main

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/cavula/forge/internal/database"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"os"
	"time"
)

func main() {
	if err := migrate(); err != nil {
		fmt.Fprintln(os.Stderr, "migration failed; check schema and owner credentials")
		os.Exit(1)
	}
}
func migrate() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	db, err := sql.Open("pgx", os.Getenv("DATABASE_URL"))
	if err != nil {
		return err
	}
	defer db.Close()
	goose.SetBaseFS(database.Migrations)
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	if len(os.Args) == 2 && os.Args[1] == "down" {
		return goose.DownContext(ctx, db, "migrations")
	}
	return goose.UpContext(ctx, db, "migrations")
}
