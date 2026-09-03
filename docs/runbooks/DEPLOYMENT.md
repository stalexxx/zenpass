# Deployment runbook

1. Run CI and verify generated API artifacts are clean.
2. Apply Terraform only from the release branch with reviewed plan output.
3. Run PostgreSQL migrations forward, then health/readiness checks.
4. Deploy API to EU staging and execute contract/E2E smoke tests.
5. Promote through internal, closed beta, and limited production stages.
6. Monitor auth abuse, error rates, latency, sync failures, and restore drills without logging user content.

