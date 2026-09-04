import { useEffect, useMemo, useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import type { AppContext } from "../lib/context.ts";
import { mount } from "../lib/react-root.ts";
import type { VaultItemData, ItemType } from "../vault/item-codec.ts";
import { generatePassword, DEFAULT_GENERATOR_OPTIONS, type GeneratorOptions } from "../crypto/generator.ts";
import { computeTotp, secondsRemaining } from "../crypto/totp.ts";
import { itemMatchesPageOrigin } from "@zkpm/domain";
import type { SearchEntry } from "../vault/search.ts";

type Mode = "view" | "edit" | "new" | "delete";

export function Vault({ ctx, initialItemId }: { ctx: AppContext; initialItemId?: string }): ReactNode {
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<string | null>(initialItemId ?? null);
  const [mode, setMode] = useState<Mode>(initialItemId ? "view" : "new");
  const [, forceRerender] = useState(0);
  const [undo, setUndo] = useState<{ mutationId: string; itemId: string; title: string } | null>(null);

  const list: SearchEntry[] = ctx.vault.search(query);

  async function offerUndo(mutationId: string, itemId: string, title: string): Promise<void> {
    ctx.announcer.status(`"${title}" deleted. Undo available while still unsynced.`);
    setUndo({ mutationId, itemId, title });
    setTimeout(() => {
      setUndo((current) => (current?.mutationId === mutationId ? null : current));
    }, 15_000);
  }

  return (
    <div className="vault-layout">
      <nav className="vault-sidebar" aria-label="Vault items">
        <div className="toolbar">
          <button
            type="button"
            onClick={() => {
              setMode("new");
              setSelected(null);
            }}
          >
            + New item
          </button>
          <button
            type="button"
            onClick={async () => {
              await ctx.vault.lock();
              ctx.navigate({ name: "unlock" });
            }}
          >
            Lock
          </button>
        </div>
        <label htmlFor="search" className="sr-only">
          Search items
        </label>
        <input
          id="search"
          type="search"
          placeholder="Search..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <ul className="item-list">
          {list.map((entry) => (
            <li key={entry.itemId}>
              <button
                type="button"
                className={entry.itemId === selected ? "item-row selected" : "item-row"}
                aria-current={entry.itemId === selected}
                onClick={() => {
                  setSelected(entry.itemId);
                  setMode("view");
                }}
              >
                <span className="item-title">{entry.title}</span>
                <span className="item-type">{entry.type}</span>
              </button>
            </li>
          ))}
        </ul>
        {list.length === 0 ? <p className="hint">No items match.</p> : null}
        <div className="toolbar">
          <button type="button" onClick={() => ctx.navigate({ name: "import" })}>
            Import
          </button>
          <button type="button" onClick={() => ctx.navigate({ name: "export" })}>
            Export
          </button>
          <button type="button" onClick={() => ctx.navigate({ name: "devices" })}>
            Devices
          </button>
        </div>
      </nav>
      <section className="vault-detail" aria-live="off">
        <DetailView
          ctx={ctx}
          mode={mode}
          selected={selected}
          setMode={setMode}
          setSelected={setSelected}
          onOfferUndo={offerUndo}
          onDataChanged={() => forceRerender((n) => n + 1)}
        />
      </section>
      {undo ? (
        <div className="undo-banner" role="status">
          {`Deleted "${undo.title}". `}
          <button
            type="button"
            onClick={async () => {
              const undone = await ctx.vault.undoDeleteIfLocal(undo.mutationId, undo.itemId);
              setUndo(null);
              if (undone) {
                ctx.announcer.status("Delete undone.");
                forceRerender((n) => n + 1);
              } else {
                ctx.announcer.error("Too late to undo — it already synced.");
              }
            }}
          >
            Undo
          </button>
        </div>
      ) : null}
    </div>
  );
}

function DetailView({
  ctx,
  mode,
  selected,
  setMode,
  setSelected,
  onOfferUndo,
  onDataChanged,
}: {
  ctx: AppContext;
  mode: Mode;
  selected: string | null;
  setMode: (mode: Mode) => void;
  setSelected: (id: string | null) => void;
  onOfferUndo: (mutationId: string, itemId: string, title: string) => void;
  onDataChanged: () => void;
}): ReactNode {
  if (mode === "new") return <ItemForm ctx={ctx} itemId={null} setMode={setMode} setSelected={setSelected} onDataChanged={onDataChanged} />;
  if (!selected) return <p className="hint">Select an item, or create a new one.</p>;
  const data = ctx.vault.getItemData(selected);
  if (!data) return <p className="hint">Item not found.</p>;
  if (mode === "edit") return <ItemForm ctx={ctx} itemId={selected} setMode={setMode} setSelected={setSelected} onDataChanged={onDataChanged} />;
  if (mode === "delete") {
    return (
      <DeleteConfirm
        ctx={ctx}
        itemId={selected}
        data={data}
        setMode={setMode}
        setSelected={setSelected}
        onOfferUndo={onOfferUndo}
      />
    );
  }
  return <ItemView ctx={ctx} itemId={selected} data={data} setMode={setMode} />;
}

// Delete confirmation is its own mode with text confirmation
// (docs/ux/flows.md: "text confirmation, not color-only cues").
function DeleteConfirm({
  ctx,
  itemId,
  data,
  setMode,
  setSelected,
  onOfferUndo,
}: {
  ctx: AppContext;
  itemId: string;
  data: VaultItemData;
  setMode: (mode: Mode) => void;
  setSelected: (id: string | null) => void;
  onOfferUndo: (mutationId: string, itemId: string, title: string) => void;
}): ReactNode {
  // Uncontrolled (read at submit time), like the rest of this app's
  // forms — no other UI needs to react to this value on every keystroke.
  async function handleSubmit(e: FormEvent<HTMLFormElement>): Promise<void> {
    e.preventDefault();
    const form = e.currentTarget;
    const input = form.elements.namedItem("deleteConfirm") as HTMLInputElement;
    if (input.value !== data.title) return;
    const mutationId = await ctx.vault.deleteItem(itemId);
    setSelected(null);
    setMode("view");
    ctx.announcer.status("Item deleted.");
    onOfferUndo(mutationId, itemId, data.title);
  }

  return (
    <form className="panel" onSubmit={handleSubmit}>
      <h1>Delete this item?</h1>
      <p className="warning">{`This cannot be undone once synced. Type the item's title ("${data.title}") to confirm.`}</p>
      <label htmlFor="deleteConfirm">Item title</label>
      <input id="deleteConfirm" name="deleteConfirm" required />
      <div className="toolbar">
        <button type="submit" className="danger">
          Delete permanently
        </button>
        <button
          type="button"
          onClick={() => {
            setMode("view");
          }}
        >
          Cancel
        </button>
      </div>
    </form>
  );
}

function Field({
  label,
  value,
  copyable = false,
  secret = false,
  ctx,
}: {
  label: string;
  value: string;
  copyable?: boolean;
  secret?: boolean;
  ctx: AppContext;
}): ReactNode {
  return (
    <div className="field">
      <span className="field-label">{label}</span>
      <span className={secret ? "field-value secret" : "field-value"}>{secret ? "••••••••" : value}</span>
      {copyable ? (
        <button
          type="button"
          onClick={async () => {
            await ctx.vault.copyToClipboard(value);
            ctx.announcer.status(`${label} copied. It will be cleared from the clipboard automatically.`);
          }}
        >
          {`Copy ${label.toLowerCase()}`}
        </button>
      ) : null}
    </div>
  );
}

function TotpDisplay({ ctx, secret }: { ctx: AppContext; secret: string }): ReactNode {
  const [code, setCode] = useState("------");
  const [seconds, setSeconds] = useState("");

  useEffect(() => {
    let cancelled = false;
    const update = async () => {
      try {
        const next = await computeTotp(secret);
        if (!cancelled) {
          setCode(next);
          setSeconds(` (${secondsRemaining()}s)`);
        }
      } catch {
        if (!cancelled) setCode("invalid secret");
      }
    };
    update();
    const timer = setInterval(update, 1000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [secret]);

  return (
    <div className="field">
      <span className="field-label">TOTP code</span>
      <span className="totp-code" aria-live="polite">
        {code}
      </span>
      <span className="totp-seconds">{seconds}</span>
      <button
        type="button"
        onClick={async () => {
          await ctx.vault.copyToClipboard(code);
          ctx.announcer.status("TOTP code copied. It will be cleared from the clipboard automatically.");
        }}
      >
        Copy code
      </button>
    </div>
  );
}

function ItemView({
  ctx,
  itemId,
  data,
  setMode,
}: {
  ctx: AppContext;
  itemId: string;
  data: VaultItemData;
  setMode: (mode: Mode) => void;
}): ReactNode {
  const originNote =
    data.url && typeof location !== "undefined" ? (
      <p className="hint">
        {itemMatchesPageOrigin([data.url], location.origin)
          ? "This page's origin matches this item."
          : "This item's URL does not match the current page origin (autofill would be refused here)."}
      </p>
    ) : null;
  const totpBlock = data.type === "totp-login" && data.totpSecret ? <TotpDisplay ctx={ctx} secret={data.totpSecret} /> : null;
  return (
    <article>
      <div className="toolbar">
        <h1>{data.title}</h1>
        <button type="button" onClick={() => setMode("edit")}>
          Edit
        </button>
      </div>
      {data.username ? <Field ctx={ctx} label="Username" value={data.username} copyable /> : null}
      {data.password ? <Field ctx={ctx} label="Password" value={data.password} copyable secret /> : null}
      {totpBlock}
      {data.url ? <Field ctx={ctx} label="URL" value={data.url} /> : null}
      {originNote}
      {data.notes ? (
        <div>
          <h2>Notes</h2>
          <p className="notes">{data.notes}</p>
        </div>
      ) : null}
      <div className="toolbar">
        <button type="button" className="danger" onClick={() => setMode("delete")}>
          Delete
        </button>
      </div>
    </article>
  );
}

function GeneratorPanel({
  options,
  onChange,
}: {
  options: GeneratorOptions;
  onChange: (opts: GeneratorOptions) => void;
}): ReactNode {
  const classes: { key: keyof GeneratorOptions; label: string }[] = [
    { key: "upper", label: "Uppercase" },
    { key: "lower", label: "Lowercase" },
    { key: "digits", label: "Digits" },
    { key: "symbols", label: "Symbols" },
  ];
  return (
    <fieldset className="generator">
      <legend>Password generator options</legend>
      <label>
        Length{" "}
        <input
          type="number"
          min={4}
          max={128}
          value={options.length}
          aria-label="Password length"
          onChange={(e) => onChange({ ...options, length: Number(e.target.value) || 12 })}
        />
      </label>
      {classes.map(({ key, label }) => (
        <label key={key}>
          <input
            type="checkbox"
            checked={options[key] as boolean}
            onChange={(e) => onChange({ ...options, [key]: e.target.checked })}
          />
          {` ${label}`}
        </label>
      ))}
    </fieldset>
  );
}

function ItemForm({
  ctx,
  itemId,
  setMode,
  setSelected,
  onDataChanged,
}: {
  ctx: AppContext;
  itemId: string | null;
  setMode: (mode: Mode) => void;
  setSelected: (id: string | null) => void;
  onDataChanged: () => void;
}): ReactNode {
  const existing = itemId ? ctx.vault.getItemData(itemId) : null;
  const initial: VaultItemData = useMemo(() => existing ?? { type: "login", title: "" }, [itemId]);
  const [error, setError] = useState("");
  const [genOptions, setGenOptions] = useState<GeneratorOptions>({ ...DEFAULT_GENERATOR_OPTIONS });
  const passwordRef = useRef<HTMLInputElement>(null);

  // Every field below is uncontrolled (defaultValue, read via
  // `form.elements` at submit time) — matching the pre-migration
  // hand-rolled version, which never mirrored form input into a
  // re-rendered state on every keystroke. The only imperative exception is
  // the password field, which "Generate" mutates directly via a ref, just
  // like the original code mutated its plain DOM node.
  async function handleSubmit(e: FormEvent<HTMLFormElement>): Promise<void> {
    e.preventDefault();
    const f = e.currentTarget;
    const get = (name: string) => (f.elements.namedItem(name) as HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement | null)?.value ?? "";
    const next: VaultItemData = {
      type: (get("type") as ItemType) || "login",
      title: get("title"),
      username: get("username") || undefined,
      password: get("password") || undefined,
      url: get("url") || undefined,
      notes: get("notes") || undefined,
      totpSecret: get("totpSecret") || undefined,
    };
    try {
      const id = await ctx.vault.saveItem(next, itemId ?? undefined);
      setSelected(id);
      setMode("view");
      ctx.announcer.status("Item saved.");
      onDataChanged();
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setError(message);
      ctx.announcer.error(message);
    }
  }

  return (
    <form className="item-form" onSubmit={handleSubmit}>
      <h1>{itemId ? "Edit item" : "New item"}</h1>
      {error ? <p className="error" role="alert">{error}</p> : null}
      <label htmlFor="type">Type</label>
      <select id="type" name="type" defaultValue={initial.type}>
        <option value="login">Login</option>
        <option value="note">Secure note</option>
        <option value="totp-login">TOTP login</option>
      </select>
      <label htmlFor="title">Title</label>
      <input id="title" name="title" required defaultValue={initial.title} />
      <label htmlFor="username">Username</label>
      <input id="username" name="username" defaultValue={initial.username ?? ""} />
      <label htmlFor="password">Password</label>
      <div className="password-row">
        <input id="password" name="password" type="text" defaultValue={initial.password ?? ""} ref={passwordRef} />
        <button
          type="button"
          onClick={() => {
            if (passwordRef.current) passwordRef.current.value = generatePassword(genOptions);
          }}
        >
          Generate
        </button>
      </div>
      <GeneratorPanel options={genOptions} onChange={setGenOptions} />
      <label htmlFor="url">URL</label>
      <input id="url" name="url" type="url" defaultValue={initial.url ?? ""} />
      <label htmlFor="totpSecret">TOTP secret (base32, only for TOTP login)</label>
      <input id="totpSecret" name="totpSecret" defaultValue={initial.totpSecret ?? ""} />
      <label htmlFor="notes">Notes</label>
      <textarea id="notes" name="notes" defaultValue={initial.notes ?? ""} />
      <div className="toolbar">
        <button type="submit">Save</button>
        <button
          type="button"
          onClick={() => {
            setMode(itemId ? "view" : "new");
            if (!itemId) setSelected(null);
          }}
        >
          Cancel
        </button>
      </div>
    </form>
  );
}

export function renderVault(root: HTMLElement, ctx: AppContext, initialItemId?: string): void {
  mount(root, <Vault ctx={ctx} initialItemId={initialItemId} />);
}
