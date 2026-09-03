# Agent contribution rules

This repository is developed through bounded multi-agent tasks. Before editing, an agent must read `docs/plan/MASTER.md`, its `docs/tasks/<ID>.md`, all referenced contracts, and relevant security documents.

- Work only inside the task's `Allowed paths`.
- Do not edit a `docs/contracts/*/v1` contract without an ADR and human security approval.
- Do not implement cryptographic primitives outside the Rust crypto-core.
- Do not log, fixture, persist, or transmit plaintext vault data, keys, passwords, or TOTP secrets.
- Add tests for every behavior and preserve contract fixtures.
- Use atomic commits prefixed by the task ID when a Git repository is available.
- Do not merge your own branch or modify another task's files.
- Report blockers through the integration agent; do not make unstated architectural decisions.
- Completion reports must follow `docs/plan/INTEGRATOR.md`.

