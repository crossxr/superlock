package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
)

func main() {
	_ = godotenv.Load()

	dbURL := os.Getenv("DATABASE_URL")
	redisURL := os.Getenv("REDIS_URL")

	ctx := context.Background()

	// 1. Flush Database
	if dbURL != "" {
		fmt.Println("Flushing Database...")
		// ── PgBouncer compatibility ──
		config, err := pgx.ParseConfig(dbURL)
		if err != nil {
			log.Fatalf("Failed to parse DB URL: %v", err)
		}
		config.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
		
		conn, err := pgx.ConnectConfig(ctx, config)
		if err != nil {
			log.Fatalf("Failed to connect to DB: %v", err)
		}
		defer conn.Close(ctx)

		// Get all tables except migrations
		rows, err := conn.Query(ctx, `
			SELECT table_name 
			FROM information_schema.tables 
			WHERE table_schema = 'public' 
			AND table_type = 'BASE TABLE'
			AND table_name != 'schema_migrations'
		`)
		if err != nil {
			log.Fatalf("Failed to list tables: %v", err)
		}
		defer rows.Close()

		var tables []string
		for rows.Next() {
			var table string
			if err := rows.Scan(&table); err != nil {
				log.Fatal(err)
			}
			tables = append(tables, table)
		}

		if len(tables) > 0 {
			query := fmt.Sprintf("TRUNCATE TABLE %s CASCADE", strings.Join(tables, ", "))
			_, err = conn.Exec(ctx, query)
			if err != nil {
				log.Fatalf("Failed to truncate tables: %v", err)
			}
			fmt.Printf("Successfully truncated %d tables\n", len(tables))
		} else {
			fmt.Println("No tables found to truncate.")
		}
	}

	// 2. Flush Redis
	if redisURL != "" {
		fmt.Println("Flushing Redis...")
		opt, err := redis.ParseURL(redisURL)
		if err != nil {
			log.Fatalf("Failed to parse Redis URL: %v", err)
		}
		rdb := redis.NewClient(opt)
		defer rdb.Close()

		status := rdb.FlushAll(ctx)
		if err := status.Err(); err != nil {
			log.Printf("Redis flush warning: %v", err)
		} else {
			fmt.Println("Successfully flushed Redis")
		}
	}
}
