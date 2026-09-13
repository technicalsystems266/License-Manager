# OrbitFS License Master V2

Authoritative backend for OrbitFS licensing, release control and deployment/update jobs.

## Authority boundary
The Website is billing/customer software. Master is the authority for licences, installation bindings, products, entitlements, signed runtime entitlements, releases, artifacts and deployment/update jobs.

Customers can still create accounts, orders and payments while Master is unavailable. Paid orders remain awaiting licence issuance until Master returns. The Billing Store must never create a substitute licence locally.

See [`docs/CONTROL-PLANE.md`](docs/CONTROL-PLANE.md) for the full system boundary and deployment/update model.

## Runtime
- Vercel-compatible Node.js API
- Dedicated Supabase PostgreSQL database
- Dedicated private Supabase Storage bucket for release artifacts
- No Cloudflare runtime dependency

## Production API
- Base URL: `https://incendiarynetworks.cc`
- API base: `https://incendiarynetworks.cc/api`
- License Master is the central authority for licence/product/install/release eligibility.

## Licence API
- `POST /api/license/issue` — idempotent issuance by order reference.
- `POST /api/license/validate` — runtime validation and signed entitlement.
- `GET /api/licenses` — Master/billing administration list.
- `POST /api/license/:id/control` — activate, suspend, terminate, unlock, component and expiry controls.
- `GET /api/license/public-key` — runtime verification key.
- `GET /api/license/revision` — Master authority revision.
- `GET /health` — liveness and dependency diagnostics.
- `GET /ready` — readiness check (database and entitlement signing key).
- `GET /admin` — administrator console (Supabase Auth email/password).

## Product authority
Products are configurable records, not deployment-code constants. The canonical products are:

- `orbitfs_base` — Panel/Base runtime; includes initial Base deployment and updater entitlement.
- `orbitfs_mcp` — shared Engine component.
- `orbitfs_apex` — shared Engine component.
- `orbitfs_studio` — shared Engine component.

Product metadata can define runtime, Engine requirement, installation limits, release channel, features, entitlement defaults, and custom metadata/rules. Future add-ons should be added as product records and release packages rather than creating another licensing authority.

## Release API
Lifecycle is `draft -> validated -> published`, with pause and withdrawal controls.

- `GET/POST /api/releases` — release discovery/creation.
- `POST /api/releases/:id/artifact` — artifact upload with SHA-256 verification.
- `POST /api/releases/:id/validate` — validation gate.
- `POST /api/releases/:id/publish` — publish only after validation.
- `POST /api/releases/:id/control` — pause or withdraw.
- `GET /api/releases/latest` — latest published release and short-lived artifact URL.

Publishing never deploys automatically. A published release becomes eligible for authenticated Billing Store/customer presentation. The customer explicitly chooses **Deploy Update**.

## Deployment/update API
- `POST /api/deployments` — queue an update/deployment for a licensed installation.
- `GET /api/deployments` — deployment queue/history.
- `GET /api/deployments/:id` — job status.
- `POST /api/deployments/execute` — submit/execute a deployment operation through the configured deployment service.
- `POST /api/deployments/sync` — synchronize deployment state.

Normal updates use an in-place strategy. They preserve the customer's existing Vercel project and Supabase data; they are not clean reinstalls. Deployment records retain previous/target versions and provider deployment references so failures can be recovered or rolled back.

## Base Deployer vs Updater
Base Deployer is a **Billing Store page** that performs the initial OrbitFS Base installation into a customer's Vercel/Supabase environment. It is not the ongoing update system.

Updater is the release/deployment mechanism used after installation. It updates Base/Panel, MCP, APEX, Studio, and future add-ons while preserving the existing installation. MCP/APEX/Studio use the shared Engine; they do not create separate Engine deployments.

## Components
`orbitfs_base`, `orbitfs_mcp`, `orbitfs_apex`, `orbitfs_studio` are entitlement components. Base runs as the Panel; MCP/APEX/Studio use the existing Engine.

## Failure/degraded operation
License Master is a hard dependency for licensing operations. If it is offline, the Billing Store may continue independent orders, invoices, and payment processing, but it cannot issue or enforce licences.

Licensing-dependent operations remain pending until Master returns:
- create/issue licence
- generate/reissue/rotate key
- activation/validation
- installation unlock/authorisation
- suspension/termination/enforcement
- entitlement checks
- release eligibility

A paid order can therefore be `PAID` while licence fulfilment is pending, then be completed when Master is available again.

## Required environment
- `DATABASE_URL`
- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`
- `MASTER_API_TOKEN`
- `BILLING_API_TOKEN`
- `DEPLOYER_API_TOKEN`
- `LICENSE_ENTITLEMENT_PRIVATE_KEY_B64`
- `SUPABASE_ANON_KEY` (publishable key used only by the sign-in page)
- `ADMIN_EMAILS` (comma-separated allowlist; alternatively set `app_metadata.role=admin`)

`SUPABASE_SERVICE_ROLE_KEY`, all Master/Billing/Deployer tokens, and the entitlement private key are server-only values. The admin page receives only the Supabase URL and publishable key, and the API verifies the Supabase access token server-side before every administrator operation. Apply migrations `0001_core.sql` through `0007_control_plane.sql` to a fresh Supabase PostgreSQL database.

For Vercel Hobby, keep request work bounded: the included configuration uses the 10-second function limit. Artifact uploads should be performed by the release pipeline, and deployment execution should be treated as a short-lived submission operation rather than a background worker.

## First-time setup

1. Create a Supabase project and run migrations `0001_core.sql` through `0007_control_plane.sql` through the supported Supabase migration workflow.
2. Enable Supabase email/password sign-in. When `SUPABASE_SERVICE_ROLE_KEY` and `SUPABASE_ANON_KEY` are configured, open `/admin` and use **First-time setup** to create the first administrator; the account receives `app_metadata.role=admin` and is signed in automatically. Alternatively, create an administrator in Supabase Authentication with an email listed in `ADMIN_EMAILS`.
3. In Vercel, add the variables from `.env.example` to the **Production** environment. Put the pooler `DATABASE_URL`, Supabase URL/keys, three server API tokens, `ADMIN_EMAILS`, and the base64 entitlement private key there. Redeploy after saving variables.
4. Open `/health`, then `/ready`. Health should be HTTP 200 and reports database, signing, API-token, and admin-auth configuration without exposing secrets. Readiness becomes HTTP 200 only after the database, signing key, and all three Master API tokens are available.
5. Open `/admin`, sign in with the Supabase administrator account, and use the configuration status table before managing licences/releases/deployments.

The admin panel can inspect service status and manage licenses, products, releases, installations, and deployments, but it intentionally cannot edit API secrets. Configure those only in Vercel Environment Variables so database credentials, bearer tokens, provider credentials, and the entitlement private key never reach browser storage or page JavaScript. The public entitlement key is available at `/api/license/public-key`.
