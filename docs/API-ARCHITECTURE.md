# OrbitFS License API Architecture

The License Master API is the central authority for OrbitFS customer, product, entitlement, licence, installation, activation, enforcement, and release-eligibility state.

## Canonical topology

```text
Customer OrbitFS Products ─────┐
                              │
V2 Billing Store ──────────────┼──> OrbitFS License API ──> Supabase/PostgreSQL
                              │
Release / Deployment System ──┘
```

The Billing Store owns storefront, checkout, orders, invoices, customer portal, billing UI, and commercial presentation. It MUST use the License API for licence/product/entitlement state and MUST NOT perform direct database writes against License Master tables.

Customer products authenticate to the License API to register installations and validate their licence/entitlements. They do not receive database credentials for the License Master database.

The release/deployment system publishes release metadata and deployment state through an authenticated API. The License API is authoritative for whether a customer, installation, product, channel, and version are eligible. The Billing Store decides how that eligible release/deployment is presented in its authenticated customer/admin UI.

## Authority boundaries

### License Master API owns

- Customers and customer references used by licensing
- Product definitions and product components
- Entitlements and entitlement rules
- Licence records and licence keys
- Installation registration and installation limits
- Activation and validation
- Suspension, termination, blocking, and enforcement state
- Release eligibility and update policy
- Release channels and compatible product/version rules
- API clients and service authentication
- Audit records for licensing operations

### V2 Billing Store owns

- Public storefront
- Product merchandising and checkout
- Orders and invoices
- Payment providers
- Customer portal UI
- Billing/customer support UI
- Commercial visibility and presentation

The Store may cache API responses for UI performance, but License Master remains authoritative for licence state.

### Release/deployment system owns

- Build/package creation
- Deployment jobs
- Deployment provider integration
- Deployment execution state and logs
- Release publication workflow

It asks License Master whether a customer/installation is entitled to a release before serving or deploying it.

## API groups

Base URL in production:

`https://incendiarynetworks.cc/api`

Canonical versioned License API prefix:

`/api/license`

### Public/runtime

- `GET /api/license/health`
- `POST /api/license/register`
- `POST /api/license/activate`
- `POST /api/license/validate`
- `GET /api/license/revision`
- `GET /api/license/releases`
- `GET /api/license/releases/:releaseId`

Runtime endpoints return only the information required by the authenticated customer installation. License keys are never returned after initial issuance except through an explicitly authorised delivery operation.

### Billing service

Authenticated service-to-service access for the Billing Store:

- customer lookup/synchronisation
- product catalogue
- entitlement lookup
- licence issuance/reissue
- licence status changes
- installation lookup
- release eligibility

The Billing Store uses its dedicated `BILLING_API_TOKEN` and is not given the master administrative token.

### Deployment service

Authenticated service-to-service access for release/deployment automation:

- publish release metadata
- check release eligibility
- register/update deployment state
- report deployment health
- request installation/release operations

The deployment service uses `DEPLOYER_API_TOKEN` and cannot perform unrelated master administration.

### Master administration

`MASTER_API_TOKEN` is reserved for privileged License Master operations and automation. Browser clients should not receive it.

## Product model

Products are data, not hard-coded application branches. Each product can define:

- `code`, name, slug, description
- active/public/purchasable state
- runtime (`panel`, `engine`, or other future runtime)
- whether an Engine is required
- installation limit
- licence duration/expiry/grace policy
- release channel policy
- version/update policy
- price/billing metadata
- feature flags
- entitlement defaults
- arbitrary product metadata

Current canonical components:

```text
orbitfs_base   -> panel
orbitfs_mcp    -> engine
orbitfs_apex   -> engine
orbitfs_studio -> engine
```

Future add-ons must use this metadata rather than adding another hard-coded component list.

## Licence vs installation vs deployment

These are deliberately separate:

**Licence:** commercial entitlement granted to a customer.

**Installation:** an authorised runtime identity consuming that licence. Installation limits and activation live here.

**Deployment:** where/how that installation is hosted, including Vercel project, URL, deployed release, health and deployment history.

A deployment may change without creating a new commercial licence. An installation may be repaired/redeployed without changing entitlement.

## Release authority

Release metadata belongs to the License API's release model when it affects licensing eligibility. Build artifacts may remain in private release storage owned by the Store/release system. The artifact location is an implementation detail; the License API remains authoritative for eligibility.

Eligibility is evaluated from:

```text
customer status
+ licence status
+ product entitlement
+ installation status
+ release channel
+ allowed version range/policy
+ suspension/termination rules
```

## Security rules

1. Customer products never connect directly to License Master PostgreSQL.
2. Billing Store never directly writes License Master licensing tables.
3. Service tokens are server-side only.
4. Runtime validation responses contain no private administrative data.
5. Installation IDs are stable identifiers, not secrets.
6. Licence keys are stored hashed; plaintext delivery is limited to controlled issuance/reissue flows.
7. Every state-changing licensing operation is audited.
8. Suspended/terminated customers are rejected before entitlement data is issued.
9. Release downloads require an eligibility check; knowing an artifact URL is insufficient.
10. Database credentials, signing private keys, Vercel tokens, and Supabase service-role keys are never stored in normal installation records.

## Why this architecture fits OrbitFS

It prevents the Billing Store, customer products, and deployment automation from implementing three slightly different versions of licensing rules. They all consume one contract. This also lets the Store UI and customer products evolve independently while preserving one authoritative licence state.