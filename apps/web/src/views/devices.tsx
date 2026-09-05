import { useEffect, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import type { AppContext } from "../lib/context.ts";
import { mount } from "../lib/react-root.ts";
import type { Device } from "@zkpm/sdk";
import { getOrCreateAccountId } from "../crypto/account-id.ts";

export function Devices({ ctx }: { ctx: AppContext }): ReactNode {
  const [devices, setDevices] = useState<Device[]>([]);
  const [error, setError] = useState("");
  const [revokeTarget, setRevokeTarget] = useState<string | null>(null);

  async function load(): Promise<void> {
    try {
      setDevices(await ctx.api.listDevices());
      setError("");
    } catch {
      setError("Could not load devices (are you online and logged in?).");
    }
  }

  useEffect(() => {
    load();
    // Loads exactly once on mount, mirroring the original render()+load()
    // call pair.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="panel">
      <h1>Devices</h1>
      <button type="button" onClick={() => ctx.navigate({ name: "vault" })}>
        Back to vault
      </button>
      <button type="button" onClick={() => ctx.navigate({ name: "extension-setup" })}>
        Set up browser extension
      </button>
      {error ? <p className="error" role="alert">{error}</p> : null}
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Last seen</th>
            <th>Status</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {devices.map((d) => (
            <tr key={d.deviceId}>
              <td>{d.name}</td>
              <td>{d.lastSeenAt ?? "never"}</td>
              <td>{d.revokedAt ? "revoked" : "active"}</td>
              <td>
                {d.revokedAt ? null : (
                  <button type="button" className="danger" onClick={() => setRevokeTarget(d.deviceId)}>
                    Revoke
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {revokeTarget ? (
        <RevokeConfirm
          deviceId={revokeTarget}
          ctx={ctx}
          onDone={async () => {
            setRevokeTarget(null);
            ctx.announcer.status("Device revoked.");
            await load();
          }}
          onError={(message) => {
            setError(message);
            ctx.announcer.error(message);
          }}
          onCancel={() => setRevokeTarget(null)}
        />
      ) : null}
    </div>
  );
}

function RevokeConfirm({
  deviceId,
  ctx,
  onDone,
  onError,
  onCancel,
}: {
  deviceId: string;
  ctx: AppContext;
  onDone: () => void;
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
      await ctx.auth.login(getOrCreateAccountId(), passwordBytes);
      await ctx.api.revokeDevice(deviceId);
      onDone();
    } catch {
      onError("Could not revoke device (re-authentication failed).");
    } finally {
      passwordBytes.fill(0);
    }
  }

  return (
    <form className="panel" onSubmit={handleSubmit}>
      <h2>Re-enter your master password to revoke this device</h2>
      <label htmlFor="password">Master password</label>
      <input id="password" name="password" type="password" required autoComplete="current-password" />
      <div className="toolbar">
        <button type="submit" className="danger">
          Revoke device
        </button>
        <button type="button" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}

export function renderDevices(root: HTMLElement, ctx: AppContext): void {
  mount(root, <Devices ctx={ctx} />);
}
