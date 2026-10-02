# Grand Horizon Hotels

Production-oriented Cloudflare Worker application for Grand Horizon Hotels.

## Current stack

- Cloudflare Workers
- Cloudflare D1
- HTML/CSS/JavaScript frontend
- Secure server-side password hashing with PBKDF2
- HTTP-only session cookies
- Server-side room purchases, balances and transaction records
- MTN Mobile Money and Airtel Money payment request flows
- Payment provider credentials/API integration is the remaining provider-specific step

## Cloudflare

Worker: `grand-horizon-hotels`

D1 database: `grand-horizon-hotels-db`

Configuration is in `wrangler.toml`.

The database schema is in `schema.sql`.

## API routes

- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `POST /api/auth/password`
- `GET /api/me`
- `POST /api/deposits`
- `POST /api/withdrawals`
- `POST /api/investments`
- `GET /api/health`

## Payment integration

Deposit and withdrawal requests are stored server-side as pending transactions. They do not pretend to move money until the real MTN/Airtel provider credentials and API details are supplied.

When the provider API is supplied, connect the provider calls to the existing deposit/withdrawal transaction references and update transaction status only after verified provider confirmation.

Never put provider API keys, secrets or access tokens in `index.html`. Keep them in Cloudflare Worker secrets.

## Deployment

Use Wrangler with the included `wrangler.toml`, or deploy the Worker directly from the Cloudflare dashboard.

