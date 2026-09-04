import { useEffect, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import type { AppContext } from "../lib/context.ts";
import { mount } from "../lib/react-root.ts";
import { getOrCreateAccountId, getDisplayEmail } from "../crypto/account-id.ts";
import { loadAccountBundle, type AccountBundle } from "../vault/account-bundle.ts";

export function Unlock({ ctx }: { ctx: AppContext }): ReactNode {
  const accountId = getOrCreateAccountId();
  const [bundle] = useState<AccountBundle | null>(() => loadAccountBundle(accountId));
  const [error, setError] = useState("");
  const email = getDisplayEmail();

  useEffect(() => {
    if (!bundle) ctx.navigate({ name: "onboarding" });
    // Only ever needs to run once, on mount, mirroring the original
    // render-time redirect.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (!bundle) return null;

  async function handleSubmit(e: FormEvent<HTMLFormElement>): Promise<void> {
    e.preventDefault();
    const form = e.currentTarget;
    const input = form.elements.namedItem("password") as HTMLInputElement;
    const passwordBytes = new TextEncoder().encode(input.value);
    input.value = "";
    try {
      // Local unlock never requires the network (docs/ux/flows.md:
      // "Offline unlock uses only the local encrypted snapshot and wrapped
      // key bundle").
      await ctx.vault.unlockWithPassword(bundle as AccountBundle, passwordBytes.slice());
      ctx.announcer.status("Vault unlocked.");
      ctx.resetInactivityTimer();
      // Best-effort, non-blocking: establish (or refresh) an authenticated
      // API session for sync. Offline/failed login does not block local
      // vault access.
      ctx.auth.login(accountId, passwordBytes).catch(() => {
        ctx.announcer.status("Unlocked offline. Sync will resume when a connection is available.");
      });
      ctx.navigate({ name: "vault" });
    } catch {
      setError("Incorrect password.");
      ctx.announcer.error("Incorrect password.");
    } finally {
      passwordBytes.fill(0);
    }
  }

  return (
    <form className="panel" onSubmit={handleSubmit}>
      <h1>Unlock your vault</h1>
      {email ? <p className="hint">Signed in as {email}</p> : null}
      {error ? <p className="error" role="alert">{error}</p> : null}
      <label htmlFor="password">Master password</label>
      <input id="password" name="password" type="password" required autoComplete="current-password" autoFocus />
      <button type="submit">Unlock</button>
    </form>
  );
}

export function renderUnlock(root: HTMLElement, ctx: AppContext): void {
  mount(root, <Unlock ctx={ctx} />);
}
