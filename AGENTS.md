# AGENTS.md - Domain-AutoCheck

## Project Overview

Domain-AutoCheck is a domain expiration monitoring system deployed on Cloudflare Workers.
It uses Cloudflare KV for storage, supports Telegram notifications, and provides a web UI
for managing domain registrations and renewal tracking. The entire application (backend +
frontend HTML/CSS/JS) lives in a single file: `src/index.js` (~6850 lines).

## Technology Stack

- **Runtime**: Cloudflare Workers (ES Module format)
- **Language**: JavaScript (vanilla, no TypeScript)
- **Storage**: Cloudflare KV (binding: `DOMAIN_MONITOR`)
- **Testing**: Vitest with `@cloudflare/vitest-pool-workers`
- **Deployment**: Wrangler CLI
- **Frontend**: Inline HTML with Bootstrap 5.3, iconfont icons, vanilla JS
- **External APIs**: WhoisJSON API, NIC.UA WHOIS, DigitalPlat WHOIS (TCP socket)

## Build / Dev / Deploy Commands

```bash
# Start local development server
npm run dev          # or: wrangler dev

# Deploy to Cloudflare Workers
npm run deploy       # or: wrangler deploy

# Run all tests
npm test             # or: npx vitest

# Run a single test file
npx vitest test/index.spec.js

# Run a single test by name
npx vitest -t "responds with Hello World"

# Run tests in watch mode (default vitest behavior)
npx vitest

# Run tests once (CI mode)
npx vitest run
```

There is no separate build step -- Wrangler handles bundling. There is no linter or
formatter configured. There is no TypeScript compilation step.

## Project Structure

```
.
├── src/
│   └── index.js          # Entire application (worker handler, API routes, HTML templates)
├── test/
│   └── index.spec.js     # Vitest tests using @cloudflare/vitest-pool-workers
├── wrangler.toml          # Cloudflare Workers configuration
├── package.json           # Dependencies and scripts
└── README.md              # User-facing documentation (Chinese)
```

## Architecture

### Entry Point (`src/index.js`)

The worker exports an ES Module default export with two handlers:

```js
export default {
  async fetch(request, env, ctx) { ... },    // HTTP request handler
  async scheduled(event, env, ctx) { ... }   // Cron trigger for notifications
};
```

### Code Organization (within `src/index.js`)

The file is organized into clearly marked sections with comment banners:

1. **Imports** (line 8): `import { connect } from 'cloudflare:sockets'`
2. **Environment injection** (`injectEnv`): Maps `env` bindings to `globalThis`
3. **Configuration constants**: Default values for logo, background, tokens, API keys
4. **Utility functions**: `formatDate()`, `jsonResponse()`
5. **WHOIS query functions**: `queryDomainWhois()`, `queryPpUaWhois()`, `queryDigitalPlatWhois()`
6. **HTML templates**: `getLoginHTML()`, `getHTMLContent()`, `getSetupHTML()` -- large template literals containing full HTML pages with embedded CSS and JS
7. **Domain CRUD functions**: `getDomains()`, `addDomain()`, `updateDomain()`, `deleteDomain()`
8. **Telegram notification**: `sendTelegramMessage()`, `checkExpiringDomains()`
9. **Request routing** (`handleRequest`): URL path-based routing, auth via cookie
10. **API handler** (`handleApiRequest`): REST-style JSON API under `/api/`

### API Routes

| Method | Path                              | Description              |
|--------|-----------------------------------|--------------------------|
| GET    | `/api/domains`                    | List all domains         |
| POST   | `/api/domains`                    | Add a domain             |
| PUT    | `/api/domains/:id`                | Update a domain          |
| DELETE | `/api/domains/:id`                | Delete a domain          |
| POST   | `/api/domains/:id/renew`          | Renew a domain           |
| GET    | `/api/telegram/config`            | Get Telegram config      |
| POST   | `/api/telegram/config`            | Save Telegram config     |
| POST   | `/api/telegram/test`              | Test Telegram message    |
| GET    | `/api/categories`                 | List categories          |
| POST   | `/api/categories`                 | Add a category           |
| PUT    | `/api/categories/:id`             | Update a category        |
| DELETE | `/api/categories/:id`             | Delete a category        |
| POST   | `/api/categories/:id/move`        | Move category order      |
| POST   | `/api/whois`                      | WHOIS domain lookup      |
| GET    | `/api/check-setup`                | Check KV binding status  |

### Authentication

- Login via POST `/login` with JSON `{ password }`.
- Session maintained with `auth=true` HttpOnly cookie (24h expiry).
- API routes require authentication; unauthenticated requests get 401.
- Password priority: env var `TOKEN` > code constant `DEFAULT_TOKEN` > fallback `"domain"`.

## Code Style Guidelines

### General

- **Language**: Plain JavaScript (ES2020+), no TypeScript, no JSX.
- **Module format**: ES Modules (`import`/`export`).
- **No build tooling**: No bundler, no transpiler, no linter configured.
- **Indentation**: Tabs for top-level code, 2-space indentation within HTML template literals.
- **Semicolons**: Used consistently at end of statements.
- **Quotes**: Single quotes for JS strings, double quotes in HTML attributes.
- **Line length**: No enforced limit; HTML template lines can be very long.

### Naming Conventions

- **Functions**: `camelCase` -- e.g., `handleRequest`, `queryDomainWhois`, `formatDate`
- **Constants**: `UPPER_SNAKE_CASE` for config -- e.g., `DEFAULT_LOGO`, `ICONFONT_CSS`
- **Variables**: `camelCase` -- e.g., `siteTitle`, `correctPassword`
- **CSS classes**: `kebab-case` -- e.g., `domain-card`, `btn-action`, `progress-circle`
- **KV keys**: Descriptive strings -- e.g., `"domains"`, `"telegram_config"`, `"categories"`

### Functions

- Use `async function name()` declarations (not arrow functions) for top-level functions.
- Arrow functions are used inline within template literal `<script>` blocks.
- Helper functions return structured objects: `{ success: boolean, ...data }`.
- Error handling wraps external calls in try/catch, returning error objects.

### Error Handling

- External API calls (WHOIS, Telegram) are wrapped in try/catch blocks.
- Errors return `{ success: false, error: error.message }` objects.
- API endpoints return JSON error responses with appropriate HTTP status codes.
- Console.error is used sparingly (only in WHOIS TCP socket errors).

### HTML Templates

- Full HTML pages are defined as template literal functions (e.g., `getLoginHTML(title)`).
- CSS is embedded in `<style>` tags within the template.
- JavaScript is embedded in `<script>` tags within the template.
- Bootstrap 5.3 CDN is used for the UI framework.
- The project uses iconfont (Alibaba icon library) for icons.
- CSS variables (`:root` / `[data-theme="dark"]`) control theming.

### Environment Variables

Configuration uses a fallback pattern: environment variable > code constant > default value.
Environment variables are injected from the `env` parameter to `globalThis` via `injectEnv()`.
Check existence with `typeof VAR !== 'undefined'` before use.

| Variable              | Purpose                        | Required |
|-----------------------|--------------------------------|----------|
| `DOMAIN_MONITOR`      | KV namespace binding           | Yes      |
| `TOKEN`               | Login password                 | No       |
| `TG_TOKEN`            | Telegram bot token             | No       |
| `TG_ID`               | Telegram chat ID               | No       |
| `SITE_NAME`           | Custom site title              | No       |
| `LOGO_URL`            | Custom logo URL                | No       |
| `BACKGROUND_URL`      | Custom background image URL    | No       |
| `WHOISJSON_API_KEY`   | WhoisJSON API key              | No       |

## Testing

Tests use `@cloudflare/vitest-pool-workers` which provides Cloudflare Workers runtime
simulation. Test files import from `cloudflare:test` for test utilities:

```js
import { env, createExecutionContext, waitOnExecutionContext, SELF } from 'cloudflare:test';
```

Two test patterns are used:
- **Unit style**: Create Request manually, call `worker.fetch(request, env, ctx)` directly.
- **Integration style**: Use `SELF.fetch()` which simulates a full Workers request cycle.

## Important Notes

- The `wrangler.toml` contains a `WHOISJSON_API_KEY` in `[vars]` -- this is a secret
  that should ideally be moved to Wrangler secrets (`wrangler secret put`).
- The entire frontend and backend are in one file. When editing UI, search for the relevant
  HTML section by CSS class names or UI text strings.
- Comments in the codebase are in Chinese (Simplified).
- The `connect` import from `cloudflare:sockets` is used for raw TCP WHOIS queries
  and is only available in the Cloudflare Workers runtime.
