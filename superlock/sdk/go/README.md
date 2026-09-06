# SuperLock Go SDK

Official Go client for SuperLock secrets management.

[![Go Reference](https://pkg.go.dev/badge/github.com/superlock/sdk-go.svg)](https://pkg.go.dev/github.com/superlock/sdk-go)

## Install

```bash
go get github.com/superlock/sdk-go
```

## Quick Start

```go
package main

import (
    "log"
    "os"

    superlock "github.com/superlock/sdk-go"
)

func main() {
    client, err := superlock.New(
        superlock.WithToken(os.Getenv("SUPERLOCK_TOKEN")),
        superlock.WithEnv(os.Getenv("SUPERLOCK_ENV_ID")),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    dbURL, ok := client.Get("DATABASE_URL")
    if ok {
        log.Println("Connected:", dbURL)
    }
}
```

## Documentation

Full docs at [superlock.superxepic.dev/docs/sdks](https://superlock.superxepic.dev/docs/sdks)

## Security

- TLS 1.2+ enforced
- Token sanitization (rejects control chars)
- Response body size limits (10 MB)
- Memory zeroing on Close()
- No secrets written to disk

## License

MIT
