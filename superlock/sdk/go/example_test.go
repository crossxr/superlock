package superlock_test

import (
	"fmt"
	"log"
	"os"

	superlock "github.com/superlock/sdk-go"
)

func Example() {
	client, err := superlock.New(
		superlock.WithToken(os.Getenv("SUPERLOCK_TOKEN")),
		superlock.WithEnv(os.Getenv("SUPERLOCK_ENV_ID")),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Fetch a single secret.
	dbURL, ok := client.Get("DATABASE_URL")
	if ok {
		fmt.Println("Database URL loaded")
		_ = dbURL
	}

	// Fetch with a default fallback.
	host := client.GetOrDefault("CACHE_HOST", "localhost:6379")
	_ = host

	// Fetch all secrets at once.
	all := client.GetAll()
	fmt.Printf("Loaded %d secrets\n", len(all))
}

func Example_mustGet() {
	client, err := superlock.New(
		superlock.WithToken(os.Getenv("SUPERLOCK_TOKEN")),
		superlock.WithEnv(os.Getenv("SUPERLOCK_ENV_ID")),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// MustGet panics if the secret is missing — good for required config.
	_ = client.MustGet("DATABASE_URL")
	_ = client.MustGet("JWT_SECRET")
}
