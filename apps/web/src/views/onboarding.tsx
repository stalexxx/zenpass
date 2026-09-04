import { useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import type { AppContext } from "../lib/context.ts";
import { mount } from "../lib/react-root.ts";
import { getOrCreateAccountId, setDisplayEmail } from "../crypto/account-id.ts";
import { saveAccountBundle, type AccountBundle } from "../vault/account-bundle.ts";
import { fromProvisionalHex, PROVISIONAL_LABEL, toProvisionalHex } from "../crypto/recovery-display.ts";

const REPORTED_PHYSICAL_MEMORY_KIB = 262_144n; // Conservative fixed value (256MB); real detection is out of C01's scope.

type Step = "form" | "reveal" | "confirm";

export function Onboarding({ ctx }: { ctx: AppContext }): ReactNode {
  const [step, setStep] = useState<Step>("form");
  const [email, setEmail] = useState("");
  const [recoveryHex, setRecoveryHex] = useState("");
  const [error, setError] = useState("");
  // Raw master-password bytes and the wrapped account bundle never need to
  // trigger a re-render themselves — they are read once at confirm time —
  // so they live in refs rather than state, exactly like the closured
  // `let password`/`let bundle` variables in the pre-migration version.
  const passwordRef = useRef<Uint8Array | null>(null);
  const bundleRef = useRef<AccountBundle | null>(null);

  async function handleFormSubmit(e: FormEvent<HTMLFormElement>): Promise<void> {
    e.preventDefault();
    const form = e.currentTarget;
    const emailInput = form.elements.namedItem("email") as HTMLInputElement;
    const passwordInput = form.elements.namedItem("password") as HTMLInputElement;
    const confirmInput = form.elements.namedItem("passwordConfirm") as HTMLInputElement;
    if (passwordInput.value.length < 12) {
      setError("Master password must be at least 12 characters.");
      return;
    }
    if (passwordInput.value !== confirmInput.value) {
      setError("Passwords do not match.");
      return;
    }
    const enteredEmail = emailInput.value;
    const passwordBytes = new TextEncoder().encode(passwordInput.value);
    passwordInput.value = "";
    confirmInput.value = "";
    try {
      ctx.announcer.status("Creating your account...");
      const accountId = getOrCreateAccountId();
      await ctx.auth.register(accountId, passwordBytes.slice());
      const vaultId = crypto.randomUUID();
      const setup = await ctx.crypto.createAccountSetup({
        password: passwordBytes,
        reportedPhysicalMemoryKiB: REPORTED_PHYSICAL_MEMORY_KIB,
        accountId,
        vaultId,
        itemId: "vault-key",
      });
      bundleRef.current = {
        accountId: setup.accountId,
        vaultId: setup.vaultId,
        itemId: setup.itemId,
        kdfParametersCbor: setup.kdfParametersCbor,
        wrappedAccountKey: setup.wrappedAccountKey,
        wrappedVaultKey: setup.wrappedVaultKey,
        wrappedItemKey: setup.wrappedItemKey,
        wrappedRecoveryKey: setup.wrappedRecoveryKey,
      };
      const hex = toProvisionalHex(setup.recoveryKey);
      setup.recoveryKey.fill(0);
      passwordRef.current = passwordBytes;
      // The setup call opened a live session under the password wrapper
      // (mirroring create_item_session_for_setup); this onboarding flow
      // does its own explicit confirm-time open via the recovery key next,
      // so close this one now rather than leaving two sessions live.
      await ctx.crypto.lock();
      setEmail(enteredEmail);
      setRecoveryHex(hex);
      setError("");
      setStep("reveal");
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setError(message);
      ctx.announcer.error(message);
    }
  }

  async function handleConfirmSubmit(e: FormEvent<HTMLFormElement>): Promise<void> {
    e.preventDefault();
    const form = e.currentTarget;
    const input = form.elements.namedItem("recoveryConfirm") as HTMLInputElement;
    const bundle = bundleRef.current;
    const password = passwordRef.current;
    if (!bundle || !password) return;
    try {
      const entered = fromProvisionalHex(input.value);
      // Real confirmation, not a checkbox: actually open the
      // recovery-wrapped account key with what the user typed, via the
      // Worker (ADR-0008's unlock_item_session_with_recovery).
      await ctx.vault.unlockWithRecovery({ ...bundle, wrappedAccountKey: bundle.wrappedRecoveryKey }, entered);
      entered.fill(0);
      saveAccountBundle(bundle);
      setDisplayEmail(email);
      await ctx.vault.lock(); // drop the recovery-opened session
      await ctx.vault.unlockWithPassword(bundle, password);
      password.fill(0);
      passwordRef.current = null;
      ctx.announcer.status("Vault created and unlocked.");
      ctx.navigate({ name: "vault" });
    } catch {
      const message = "That doesn't match the recovery key shown. Please re-check and try again.";
      setError(message);
      ctx.announcer.error(message);
    }
  }

  if (step === "form") {
    return (
      <form className="panel" onSubmit={handleFormSubmit}>
        <h1>Create your vault</h1>
        <p>Your master password never leaves this device. We cannot recover it for you.</p>
        {error ? <p className="error" role="alert">{error}</p> : null}
        <label htmlFor="email">Email (local label only — not sent to the server)</label>
        <input id="email" name="email" type="email" required autoComplete="email" />
        <label htmlFor="password">Master password</label>
        <input
          id="password"
          name="password"
          type="password"
          required
          autoComplete="new-password"
          aria-describedby="pw-help"
        />
        <p id="pw-help" className="hint">
          At least 12 characters. This is the only password you'll ever need to remember.
        </p>
        <label htmlFor="passwordConfirm">Confirm master password</label>
        <input id="passwordConfirm" name="passwordConfirm" type="password" required autoComplete="new-password" />
        <button type="submit">Create vault</button>
      </form>
    );
  }

  if (step === "reveal") {
    return (
      <div className="panel">
        <h1>Save your recovery key</h1>
        <p className="warning">
          Support cannot recover a lost master password without this recovery key. If you lose both, your data is
          permanently unrecoverable.
        </p>
        <p className="hint">{PROVISIONAL_LABEL}</p>
        <pre className="recovery-key" aria-label="Recovery key">
          {recoveryHex}
        </pre>
        <button
          type="button"
          onClick={() => {
            setStep("confirm");
            setError("");
          }}
        >
          I've saved it — continue
        </button>
      </div>
    );
  }

  return (
    <form className="panel" onSubmit={handleConfirmSubmit}>
      <h1>Confirm your recovery key</h1>
      <p>Re-enter the recovery key exactly as shown on the previous screen.</p>
      {error ? <p className="error" role="alert">{error}</p> : null}
      <label htmlFor="recoveryConfirm">Recovery key</label>
      <input id="recoveryConfirm" name="recoveryConfirm" type="text" required autoComplete="off" spellCheck={false} />
      <button type="submit">Confirm and open my vault</button>
      <button type="button" onClick={() => setStep("reveal")}>
        Show it again
      </button>
    </form>
  );
}

/** Imperative mount entry point, kept for callers (tests) that render this
 * view directly into a container rather than through the top-level App. */
export function renderOnboarding(root: HTMLElement, ctx: AppContext): void {
  mount(root, <Onboarding ctx={ctx} />);
}
