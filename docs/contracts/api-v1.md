# api/v1

The OpenAPI document is the source of truth and must be generated before client DTOs.

The canonical machine-readable contract is [`packages/contracts/openapi.yaml`](../../packages/contracts/openapi.yaml). Shared TypeScript domain types and JSON Schemas live in `packages/contracts/src/` and `packages/contracts/schemas/`.

All endpoints are under `/v1`; the OpenAPI server URL is illustrative and must be replaced by deployment configuration.

## Endpoint groups

- `/auth/opaque/register`, `/auth/opaque/login`, `/auth/refresh`, `/auth/logout`
- `/auth/webauthn/*`
- `/account/key-bundle`, `/account/recovery-reset`, `/account/delete`
- `/devices`, `/devices/{deviceId}`, `/devices/{deviceId}/revoke`
- `/vaults/{vaultId}/items`, `/vaults/{vaultId}/changes`

All item payloads are opaque ciphertext. Request bodies, tokens, passwords, and ciphertext are excluded from logs.
