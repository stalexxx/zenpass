# Integration agent operating procedure

1. Read `MASTER.md`, `STATUS.md`, and every task report before dispatching the next wave.
2. Confirm dependencies and allowed paths; mark only dependency-free tasks `READY`.
3. Create/bind one orchestration Run, create a Task for each ready package, and dispatch workers with supervised worktree execution.
4. Wait for `worker_done`, `question`, or `escalation`; process the entire delivery before acknowledging it.
5. For a successful worker, inspect the report, run the task verification commands, then release or explicitly reuse the worker terminal.
6. Merge only with passing CI and no contract drift. Update `STATUS.md` and the DAG after every merge.
7. For contract/security changes, create an ADR and pause dependent tasks until human approval.
8. Before Q01, run the complete generated-client, migration, vector, and cross-package suite.
9. Before R01, require H02 evidence, backup restore evidence, and a human release sign-off.

## Merge checklist

- [ ] Task status is `REVIEW` and report is present.
- [ ] Changed paths are within `Allowed paths`.
- [ ] No generated artifacts or lockfile drift is unexplained.
- [ ] Unit, integration, contract, and package build checks pass.
- [ ] API and crypto fixtures remain compatible.
- [ ] Security implications are documented.
- [ ] Migration is forward-compatible and restore-tested.
- [ ] `STATUS.md` is updated.

## Completion report template

```text
Task:
Status:
Commits:
Changed paths:
Contract changes: none | list
Verification commands and results:
Known limitations:
Security considerations:
Follow-up tasks:
```

