package database

import "embed"

// Migrations embeds the versioned schema for offline migration execution.
//
//go:embed migrations/*.sql
var Migrations embed.FS
