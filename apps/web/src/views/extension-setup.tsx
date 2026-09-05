// ADR-0011 D1/G1: explicit web publication of the account key bundle and a
// copyable accountId, so a separate extension login can discover and open
// the same account. This view never invents new keys and never overwrites
// a conflicting remote bundle automatically — a 409 stops here and asks
// the user to resolve using this (already-unlocked, authoritative) local
// context.
import { useState } from "react";
import type { ReactNode } from "react";
import type { AppContext } from "../lib/context.ts";
import { mount } from "../lib/react-root.ts";
import { getOrCreateAccountId } from "../crypto/account-id.ts";
import { buildAccountBundle } from "@zkpm/sdk";

type Status =
  | { kind: "idle" }
  | { kind: "publishing" }
  | { kind: "published" }
  | { kind: "conflict"; currentVersion: number | null }
  | { kind: "error"; message: string };

export function ExtensionSetup({ ctx }: { ctx: AppContext }): ReactNode {
  const accountId = getOrCreateAccountId();
  const [status, setStatus] = useState<Status>({ kind: "idle" });
  const [copied, setCopied] = useState(false);

  async function copyAccountId(): Promise<void> {
    try {
      await navigator.clipboard.writeText(accountId);
      setCopied(true);
      ctx.announcer.status("Account ID copied.");
    } catch {
      // Clipboard permission denied or unavailable: the value is still
      // selectable/visible in the <code> element below.
      setCopied(false);
    }
  }

  async function publish(): Promise<void> {
    const local = ctx.vault.accountBundle;
    if (!local) {
      setStatus({ kind: "error", message: "Unlock your vault before publishing." });
      return;
    }
    setStatus({ kind: "publishing" });
    try {
      const existing = await ctx.api.getKeyBundle();
      const attemptedVersion = existing.status === 200 ? existing.keyBundle.version + 1 : 1;
      const bundle = buildAccountBundle(local);
      const result = await ctx.api.putKeyBundle({ bundle, version: attemptedVersion });
      if (result.status === 409) {
        setStatus({ kind: "conflict", currentVersion: result.conflict.currentVersion });
        ctx.announcer.error("A different bundle is already published for this account.");
        return;
      }
      // Confirm the exact bytes/revision landed before calling this
      // "ready for extension" (ADR-0011 G1) — never trust the 204 alone.
      const verify = await ctx.api.getKeyBundle();
      if (verify.status !== 200 || verify.keyBundle.bundle !== bundle || verify.keyBundle.version !== attemptedVersion) {
        setStatus({ kind: "error", message: "Publish could not be verified. Please try again." });
        return;
      }
      setStatus({ kind: "published" });
      ctx.announcer.status("Account bundle published for extension use.");
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setStatus({ kind: "error", message });
      ctx.announcer.error(message);
    }
  }

  return (
    <div className="panel">
      <h1>Set up the browser extension</h1>
      <p>
        The extension signs in independently with its own master-password login. It never reads this browser's
        storage or session. Give it your account ID below, then publish your key bundle so it can open your vault.
      </p>

      <h2>Your account ID</h2>
      <p className="hint">Not a secret — safe to copy into the extension's sign-in screen.</p>
      <code aria-label="Account ID">{accountId}</code>
      <button type="button" onClick={copyAccountId}>
        {copied ? "Copied" : "Copy account ID"}
      </button>

      <h2>Publish key bundle</h2>
      <p className="hint">
        Publishing does not create or change any key. It only makes your existing wrapped keys available for the
        extension to read after its own unlock.
      </p>
      {status.kind === "error" ? (
        <p className="error" role="alert">
          {status.message}
        </p>
      ) : null}
      {status.kind === "conflict" ? (
        <p className="error" role="alert">
          A different key bundle (revision {status.currentVersion ?? "unknown"}) is already published for this
          account from elsewhere. Publishing was not applied so nothing was overwritten. Resolve this from the
          device that published it, or contact support before retrying.
        </p>
      ) : null}
      {status.kind === "published" ? (
        <p role="status">Published. The extension can now sign in and open this account.</p>
      ) : null}
      <button type="button" onClick={publish} disabled={status.kind === "publishing"}>
        {status.kind === "publishing" ? "Publishing..." : "Publish key bundle"}
      </button>

      <button type="button" onClick={() => ctx.navigate({ name: "vault" })}>
        Back to vault
      </button>
    </div>
  );
}

/** Imperative mount entry point, kept for callers (tests) that render this
 * view directly into a container rather than through the top-level App. */
export function renderExtensionSetup(root: HTMLElement, ctx: AppContext): void {
  mount(root, <ExtensionSetup ctx={ctx} />);
}
