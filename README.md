# Grand Horizon Hotels — Cloudflare foundation

This branch contains the initial Cloudflare Workers backend for the hotel member portal.

## Included

- Cloudflare Worker API written in TypeScript
- D1 schema for members and bookings
- R2 asset storage binding
- Health, member, booking, and asset routes
- Wrangler local development and deployment configuration

## Setup

```bash
npm install
npx wrangler login
npx wrangler d1 create grand-horizon-hotels-db
npx wrangler r2 bucket create grand-horizon-hotels-assets
```

Copy the D1 database ID into `wrangler.toml`, then initialize the local database:

```bash
npm run db:init
npm run dev
```

For production, apply the schema remotely and deploy:

```bash
npx wrangler d1 execute grand-horizon-hotels-db --remote --file=./schema.sql
npm run deploy
```

## API examples

```bash
curl http://localhost:8787/api/health
curl http://localhost:8787/api/members
curl -X POST http://localhost:8787/api/members \
  -H 'content-type: application/json' \
  -d '{"email":"guest@example.com","firstName":"Alex","lastName":"Guest"}'
```

Authentication, rate limiting, and production secrets should be added before exposing member data publicly.
