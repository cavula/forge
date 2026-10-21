package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cavula/forge/internal/platform"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("server stopped")
		os.Exit(1)
	}
}
func run(logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	tp := sdktrace.NewTracerProvider(sdktrace.WithResource(resource.Default()))
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	defer func() { _ = tp.Shutdown(context.Background()) }()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		return errors.New("invalid database configuration")
	}
	defer pool.Close()
	server := &http.Server{Addr: ":8080", ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: time.Minute,
		Handler: platform.Handler(func(ctx context.Context) error {
			check, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			if err := pool.Ping(check); err != nil {
				return err
			}
			var ok bool
			if err := pool.QueryRow(check, "SELECT to_regclass('public.orgs') IS NOT NULL").Scan(&ok); err != nil {
				return err
			}
			if !ok {
				return errors.New("schema missing")
			}
			return nil
		}),
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	logger.Info("server listening", "address", server.Addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
