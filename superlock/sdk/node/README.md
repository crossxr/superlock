# @superlock/node

Official Node.js/TypeScript SDK for SuperLock secrets management.

## Install

```bash
npm install @superlock/node
```

Optional WebSocket support:
```bash
npm install ws
```

## Quick Start

```typescript
import { SuperLockClient } from '@superlock/node';

const client = new SuperLockClient({
  token: process.env.SUPERLOCK_TOKEN!,
  env: process.env.SUPERLOCK_ENV_ID!,
});

await client.ready();

const dbUrl = await client.get('DATABASE_URL');
const all = await client.getAll();

// On shutdown
client.destroy();
```

## Next.js Usage

Works in API routes, `getServerSideProps`, middleware, and server components.

**Important:** Server-side only. Never expose your token to the client bundle.

## Documentation

Full docs at [superlock.superxepic.dev/docs/sdks](https://superlock.superxepic.dev/docs/sdks)

## Security

- HTTPS enforced in production
- Token sanitization (rejects control chars)
- Response body size limits (10 MB)
- Content-Type validation
- Memory zeroing on destroy()
- No secrets written to disk

## License

MIT
