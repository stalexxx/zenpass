import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import type { AppContext } from "../lib/context.ts";
import { mount } from "../lib/react-root.ts";
import type { Conflict } from "@zkpm/sdk";
import type { DecryptedConflict } from "../vault/vault-session.ts";

/** Renders a field-level comparison of one already-decrypted conflict.
 * SyncEngine never decrypts; VaultSession.decryptConflict does that using
 * the still-open session, and this view just displays the result. */
export function Conflicts({ ctx, conflicts }: { ctx: AppContext; conflicts: Conflict[] }): ReactNode {
  const [index, setIndex] = useState(0);
  const [decrypted, setDecrypted] = useState<DecryptedConflict | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    if (index >= conflicts.length) {
      setDecrypted(null);
      return;
    }
    ctx.vault
      .decryptConflict(conflicts[index])
      .then((result) => {
        if (!cancelled) {
          setDecrypted(result);
          setError("");
        }
      })
      .catch(() => {
        if (!cancelled) {
          setError("Could not decrypt this conflict.");
          setDecrypted(null);
        }
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [index, conflicts]);

  function backButton(): ReactNode {
    return (
      <button type="button" onClick={() => ctx.navigate({ name: "vault" })}>
        Back to vault
      </button>
    );
  }

  if (conflicts.length === 0) {
    return (
      <div className="panel">
        <h1>Conflicts</h1>
        <p>No conflicts.</p>
        {backButton()}
      </div>
    );
  }

  if (!decrypted) {
    return (
      <div className="panel">
        <h1>Conflicts</h1>
        {error ? <p className="error" role="alert">{error}</p> : null}
        {backButton()}
      </div>
    );
  }

  const { current, attempted } = decrypted;

  return (
    <div className="panel">
      <h1>{`Conflict ${index + 1} of ${conflicts.length}`}</h1>
      <p className="hint">
        {`Server version updated ${current.updatedAt} (revision ${current.revision}). Your change was based on revision ${attempted.baseRevision}.`}
      </p>
      <table className="diff-table">
        <thead>
          <tr>
            <th>Field</th>
            <th>Current (server)</th>
            <th>Your change</th>
          </tr>
        </thead>
        <tbody>
          <FieldRow label="Title" a={current.data.title} b={attempted.data.title} />
          <FieldRow label="Username" a={current.data.username} b={attempted.data.username} />
          <FieldRow label="Password" a={current.data.password ? "••••••••" : undefined} b={attempted.data.password ? "••••••••" : undefined} />
          <FieldRow label="URL" a={current.data.url} b={attempted.data.url} />
          <FieldRow label="Notes" a={current.data.notes} b={attempted.data.notes} />
        </tbody>
      </table>
      <div className="toolbar">
        <button
          type="button"
          onClick={async () => {
            await ctx.vault.resolveConflict(conflicts[index], current.data);
            setIndex((i) => i + 1);
          }}
        >
          Keep server version
        </button>
        <button
          type="button"
          onClick={async () => {
            await ctx.vault.resolveConflict(conflicts[index], attempted.data);
            setIndex((i) => i + 1);
          }}
        >
          Keep my version
        </button>
      </div>
      {backButton()}
    </div>
  );
}

function FieldRow({ label, a, b }: { label: string; a?: string; b?: string }): ReactNode {
  const changed = a !== b;
  return (
    <tr className={changed ? "diff-changed" : undefined}>
      <th>{label}</th>
      <td>{a ?? <em>(empty)</em>}</td>
      <td>{b ?? <em>(empty)</em>}</td>
    </tr>
  );
}

export function renderConflicts(root: HTMLElement, ctx: AppContext, conflicts: Conflict[]): void {
  mount(root, <Conflicts ctx={ctx} conflicts={conflicts} />);
}
