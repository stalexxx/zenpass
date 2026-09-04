import { useState } from "react";
import type { FormEvent, ReactNode } from "react";
import type { AppContext } from "../lib/context.ts";
import { mount } from "../lib/react-root.ts";
import { getOrCreateAccountId } from "../crypto/account-id.ts";

/** Builds the encrypted export payload: raw ItemRecords (still
 * ciphertext), never decrypted. This is the *default* and always-safe
 * export path — no gate needed, since nothing plaintext ever leaves
 * memory. */
async function buildEncryptedExport(ctx: AppContext): Promise<string> {
  const bundle = ctx.vault.accountBundle;
  if (!bundle) throw new Error("vault is locked");
  const items = await ctx.repo.listItems(bundle.vaultId);
  return JSON.stringify({ format: "zkpm-encrypted-export/v1", vaultId: bundle.vaultId, items }, null, 2);
}

/** Builds the plaintext export payload by decrypting every item in
 * memory, right before this function returns the string — never persisted
 * partway, never logged. Callers must have already gated this behind
 * re-authentication and an explicit second confirmation (see the export
 * view below); this function itself does not enforce that, by design (the
 * view owns the UX-level gate, and unit tests exercise this function and
 * the gate independently). */
function buildPlaintextExport(ctx: AppContext): string {
  const rows = ctx.vault
    .list()
    .map((entry) => ctx.vault.getItemData(entry.itemId))
    .filter((data): data is NonNullable<typeof data> => data !== null);
  return JSON.stringify({ format: "zkpm-plaintext-export/v1", items: rows }, null, 2);
}

function download(filename: string, content: string): void {
  const blob = new Blob([content], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

type Stage = "menu" | "confirm-plaintext" | "reauth";

export function Export({ ctx }: { ctx: AppContext }): ReactNode {
  const [stage, setStage] = useState<Stage>("menu");
  const [reauthError, setReauthError] = useState("");

  if (stage === "menu") {
    return (
      <div className="panel">
        <h1>Export</h1>
        <button type="button" onClick={() => ctx.navigate({ name: "vault" })}>
          Back to vault
        </button>
        <p>Encrypted export is safe to store anywhere — it contains only ciphertext.</p>
        <button
          type="button"
          onClick={async () => {
            const json = await buildEncryptedExport(ctx);
            download("vault-export-encrypted.json", json);
            ctx.announcer.status("Encrypted export downloaded.");
          }}
        >
          Download encrypted export
        </button>
        <hr />
        <p className="warning">
          Plaintext export writes every password and secret to a file in the clear. Anyone with that file can read
          your vault.
        </p>
        <button type="button" className="danger" onClick={() => setStage("confirm-plaintext")}>
          Export as plaintext...
        </button>
      </div>
    );
  }

  if (stage === "confirm-plaintext") {
    return <ConfirmPlaintext onConfirm={() => setStage("reauth")} onCancel={() => setStage("menu")} />;
  }

  return (
    <Reauth
      ctx={ctx}
      error={reauthError}
      onSuccess={() => setStage("menu")}
      onError={(message) => setReauthError(message)}
      onCancel={() => setStage("menu")}
    />
  );
}

function ConfirmPlaintext({ onConfirm, onCancel }: { onConfirm: () => void; onCancel: () => void }): ReactNode {
  // Deliberately uncontrolled (read at submit time, like the rest of this
  // app's forms) rather than mirrored into React state on every
  // keystroke: this input's only job is a one-shot confirmation check,
  // and there is no other UI that needs to react to it changing live.
  function handleSubmit(e: FormEvent<HTMLFormElement>): void {
    e.preventDefault();
    const form = e.currentTarget;
    const input = form.elements.namedItem("confirm") as HTMLInputElement;
    if (input.value !== "EXPORT PLAINTEXT") return;
    onConfirm();
  }

  return (
    <form className="panel" onSubmit={handleSubmit}>
      <h1>Confirm plaintext export</h1>
      <p className="warning">
        This writes unencrypted passwords, notes, and TOTP secrets to a file on disk. Type "EXPORT PLAINTEXT" to
        confirm you understand the risk.
      </p>
      <input required name="confirm" aria-label="Type EXPORT PLAINTEXT to confirm" />
      <div className="toolbar">
        <button type="submit" className="danger">
          Continue
        </button>
        <button type="button" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}

function Reauth({
  ctx,
  error,
  onSuccess,
  onError,
  onCancel,
}: {
  ctx: AppContext;
  error: string;
  onSuccess: () => void;
  onError: (message: string) => void;
  onCancel: () => void;
}): ReactNode {
  async function handleSubmit(e: FormEvent<HTMLFormElement>): Promise<void> {
    e.preventDefault();
    const form = e.currentTarget;
    const input = form.elements.namedItem("password") as HTMLInputElement;
    const passwordBytes = new TextEncoder().encode(input.value);
    input.value = "";
    try {
      // Re-authentication per docs/ux/flows.md: plaintext export requires
      // re-entering the master password against the live OPAQUE login,
      // not just re-using the already-unlocked session.
      await ctx.auth.login(getOrCreateAccountId(), passwordBytes);
      const json = buildPlaintextExport(ctx);
      download("vault-export-PLAINTEXT.json", json);
      ctx.announcer.status("Plaintext export downloaded.");
      onSuccess();
    } catch {
      onError("Re-authentication failed.");
      ctx.announcer.error("Re-authentication failed.");
    } finally {
      passwordBytes.fill(0);
    }
  }

  return (
    <form className="panel" onSubmit={handleSubmit}>
      <h1>Re-enter your master password</h1>
      {error ? <p className="error" role="alert">{error}</p> : null}
      <label htmlFor="password">Master password</label>
      <input id="password" name="password" type="password" required autoComplete="current-password" />
      <div className="toolbar">
        <button type="submit" className="danger">
          Export plaintext now
        </button>
        <button type="button" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}

export function renderExport(root: HTMLElement, ctx: AppContext): void {
  mount(root, <Export ctx={ctx} />);
}

export { buildEncryptedExport, buildPlaintextExport };
