package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/joho/godotenv"
	goredis "github.com/redis/go-redis/v9"

	"github.com/nan0/backend/internal/api"
	"github.com/nan0/backend/internal/cache"
	"github.com/nan0/backend/internal/crypto"
	"github.com/nan0/backend/internal/dynamic"
	"github.com/nan0/backend/internal/email"
	"github.com/nan0/backend/internal/model"
	"github.com/nan0/backend/internal/netguard"
	"github.com/nan0/backend/internal/rotation"
	"github.com/nan0/backend/internal/store"
	"github.com/nan0/backend/internal/ws"
)

func main() {
	_ = godotenv.Load()

	if dsn := os.Getenv("SENTRY_DSN"); dsn != "" {
		if err := sentry.Init(sentry.ClientOptions{
			Dsn:              dsn,
			Environment:      os.Getenv("APP_ENV"),
			TracesSampleRate: 0.2,
			EnableTracing:    true,
		}); err != nil {
			log.Printf("Sentry init failed: %v", err)
		}
		defer sentry.Flush(2 * time.Second)
		log.Println("Sentry initialized")
	}

	db, err := store.New(os.Getenv("DATABASE_URL"))
	if err != nil {
		sentry.CaptureException(err)
		log.Fatalf("DB connect failed: %v", err)
	}
	defer db.Close()

	if err := store.Migrate(os.Getenv("DATABASE_URL"), "migrations"); err != nil {
		log.Printf("Migration warning: %v", err)
	}

	rdb, err := cache.New(os.Getenv("REDIS_URL"))
	if err != nil {
		log.Printf("Redis connect warning: %v", err)
	}

	// WebSocket hub
	hub := ws.NewHub(strings.Split(os.Getenv("ALLOWED_ORIGINS"), ","))

	// Email client (Resend)
	var emailClient *email.Client
	if key := os.Getenv("RESEND_API_KEY"); key != "" {
		emailClient = email.New(key,
			os.Getenv("EMAIL_FROM"),
			os.Getenv("EMAIL_FROM_NAME"),
		)
	}

	// Outbound egress guard. Private addresses are blocked unless a
	// single-tenant deployment explicitly opts out.
	allowPrivateEgress := strings.EqualFold(os.Getenv("SUPERLOCK_ALLOW_PRIVATE_EGRESS"), "true")
	guard := netguard.New(allowPrivateEgress)
	if allowPrivateEgress {
		log.Println("WARNING: SUPERLOCK_ALLOW_PRIVATE_EGRESS=true — outbound SSRF protection is disabled")
	}

	// Rotation worker
	var worker *rotation.Worker
	if rdb != nil {
		var cryptoEngine *crypto.Engine
		if key := os.Getenv("ENCRYPTION_KEY"); key != "" {
			cryptoEngine, _ = crypto.New(key)
		}
		var rawRedis *goredis.Client
		if rdb != nil {
			rawRedis = rdb.Raw()
		}
		worker = rotation.NewWorker(db, cryptoEngine, hub, emailClient, rawRedis, guard)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go worker.Run(ctx)
		log.Println("Rotation worker started")
	}

	router := api.NewRouter(api.Config{
		DB:             db,
		Cache:          rdb,
		JWTSecret:      os.Getenv("SUPABASE_JWT_SECRET"),
		SupabaseURL:    os.Getenv("SUPABASE_URL"),
		EncryptionKey:  os.Getenv("ENCRYPTION_KEY"),
		Guard:          guard,
		AuditHMACKey:   os.Getenv("AUDIT_HMAC_KEY"),
		AllowedOrigins: os.Getenv("ALLOWED_ORIGINS"),
		Email:          emailClient,
		Hub:            hub,
		Worker:         worker,
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%s", port),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("SuperLock API server starting on :%s", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			sentry.CaptureException(err)
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Phase 3: Start dynamic secret lease reaper
	go dynamic.ExpiredLeaseReaper(context.Background(),
		func(ctx context.Context) ([]*model.DynamicSecretLease, error) {
			return db.ListExpiredLeases(ctx)
		},
		func(ctx context.Context, l *model.DynamicSecretLease) error {
			// Attempt revocation from the DB backend
			if l.Backend == "postgres" {
				_ = dynamic.RevokePostgresLease(ctx, l.DatabaseURL, l.Username)
			}
			return db.RevokeLease(ctx, l.ID)
		},
	)

	<-quit
	log.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Forced shutdown: %v", err)
	}
	log.Println("Server stopped")
}
