/**
 * Extension-local session state machine (ADR-0011 D4/D5).
 *
 * Starts locked. Locking increments a generation counter that invalidates
 * every outstanding offer, capability, port and late async result. Only
 * trusted popup activity extends the inactivity deadline; untrusted
 * content traffic never does. Deadlines are checked before every action,
 * not only from timer callbacks, so a killed or stalled service worker
 * cannot resurrect a stale session. No vault data lives here; this is
 * lifecycle state only.
 */

export type LockReason =
  | "explicit"
  | "popup-closed"
  | "timeout"
  | "error"
  | "evicted"
  | "auth-failed"
  | "startup";

export const POPUP_INACTIVITY_LIMIT_MS = 300_000;

export class SessionStateMachine {
  #now: () => number;
  #generation = 1;
  #lastTrustedActivityAt: number | null = null;
  #active = false;
  #lastLockReason: LockReason = "startup";

  constructor(now: () => number = () => Date.now()) {
    this.#now = now;
  }

  get generation(): number {
    return this.#generation;
  }

  get locked(): boolean {
    return !this.#active;
  }

  get lastLockReason(): LockReason {
    return this.#lastLockReason;
  }

  /**
   * Locks the session. Every call increments the generation so pending
   * promises and one-use capabilities from the previous generation can
   * never complete against fresh state.
   */
  lock(reason: LockReason): void {
    this.#generation += 1;
    this.#active = false;
    this.#lastTrustedActivityAt = null;
    this.#lastLockReason = reason;
  }

  /**
   * Marks the session active. Reserved for the C04-G1 independent unlock
   * wiring (OPAQUE login plus key-bundle open inside the background);
   * there is intentionally no production caller before that merge, so the
   * shipped extension stays locked by default.
   */
  markUnlocked(): void {
    if (this.#active) return;
    this.#active = true;
    this.#lastTrustedActivityAt = this.#now();
  }

  /** Only trusted popup activity may reset the inactivity deadline. */
  noteTrustedPopupActivity(): void {
    if (this.#active) this.#lastTrustedActivityAt = this.#now();
  }

  /** Fails closed when the five-minute trusted-activity deadline passed. */
  ensureActive(): void {
    if (!this.#active) return;
    const last = this.#lastTrustedActivityAt;
    if (last === null || this.#now() - last > POPUP_INACTIVITY_LIMIT_MS) this.lock("timeout");
  }
}
