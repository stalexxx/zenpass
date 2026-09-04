import { useState } from "react";
import type { ChangeEvent, ReactNode } from "react";
import type { AppContext } from "../lib/context.ts";
import { mount } from "../lib/react-root.ts";
import { normalizeCsv, normalizeBitwardenJson, normalizeOnePasswordCsv, normalizeEnpassJson, ImportSizeError } from "@zkpm/importers";
import type { NormalizedItem, NormalizeResult } from "@zkpm/domain";

type Format = "csv" | "bitwarden" | "1password" | "enpass";

function normalize(format: Format, text: string): NormalizeResult {
  switch (format) {
    case "csv":
      return normalizeCsv(text);
    case "bitwarden":
      return normalizeBitwardenJson(text);
    case "1password":
      return normalizeOnePasswordCsv(text);
    case "enpass":
      return normalizeEnpassJson(text);
  }
}

function toVaultData(item: NormalizedItem) {
  const type: "login" | "totp-login" | "note" = item.totp ? "totp-login" : item.username || item.password ? "login" : "note";
  return {
    type,
    title: item.title,
    username: item.username,
    password: item.password,
    url: item.url,
    notes: item.notes,
    totpSecret: item.totp?.secret,
  };
}

export function Import({ ctx }: { ctx: AppContext }): ReactNode {
  const [format, setFormat] = useState<Format>("csv");
  const [result, setResult] = useState<NormalizeResult | null>(null);
  const [fileError, setFileError] = useState("");

  async function handleFileChange(e: ChangeEvent<HTMLInputElement>): Promise<void> {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      setResult(normalize(format, text));
      setFileError("");
    } catch (err) {
      setResult(null);
      setFileError(err instanceof ImportSizeError ? err.message : "Could not parse this file.");
    }
  }

  async function handleImport(res: NormalizeResult): Promise<void> {
    let imported = 0;
    let failed = 0;
    for (const item of res.items) {
      try {
        await ctx.vault.saveItem(toVaultData(item));
        imported += 1;
      } catch {
        failed += 1;
      }
    }
    ctx.announcer.status(failed > 0 ? `Imported ${imported} item(s); ${failed} could not be saved.` : `Imported ${imported} item(s).`);
    ctx.navigate({ name: "vault" });
  }

  return (
    <div className="panel">
      <h1>Import</h1>
      <button type="button" onClick={() => ctx.navigate({ name: "vault" })}>
        Back to vault
      </button>
      <label htmlFor="format">Source format</label>
      <select
        id="format"
        value={format}
        onChange={(e) => {
          setFormat(e.target.value as Format);
          setResult(null);
        }}
      >
        <option value="csv">Generic CSV</option>
        <option value="bitwarden">Bitwarden (JSON)</option>
        <option value="1password">1Password (CSV)</option>
        <option value="enpass">Enpass (JSON)</option>
      </select>
      <label htmlFor="file">Export file</label>
      <input id="file" type="file" accept=".csv,.json,.txt" onChange={handleFileChange} />
      {fileError ? <p className="error" role="alert">{fileError}</p> : null}
      {result ? <PreviewSection result={result} onImport={handleImport} /> : null}
    </div>
  );
}

function PreviewSection({
  result,
  onImport,
}: {
  result: NormalizeResult;
  onImport: (res: NormalizeResult) => void;
}): ReactNode {
  return (
    <div>
      <h2>{`Preview: ${result.items.length} item(s) found`}</h2>
      {result.issues.length > 0 ? (
        <details>
          <summary>{`${result.issues.length} warning(s) — unsupported or truncated fields`}</summary>
          <ul>
            {result.issues.map((i, index) => (
              <li key={index}>{`Row ${i.index}: ${i.reason}`}</li>
            ))}
          </ul>
        </details>
      ) : null}
      <table className="preview-table">
        <thead>
          <tr>
            <th>Title</th>
            <th>Username</th>
            <th>URL</th>
            <th>Has password</th>
            <th>Has TOTP</th>
          </tr>
        </thead>
        <tbody>
          {result.items.slice(0, 50).map((item, index) => (
            <tr key={index}>
              <td>{item.title}</td>
              <td>{item.username ?? ""}</td>
              <td>{item.url ?? ""}</td>
              <td>{item.password ? "yes" : "no"}</td>
              <td>{item.totp ? "yes" : "no"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {result.items.length > 50 ? <p className="hint">{`...and ${result.items.length - 50} more.`}</p> : null}
      <button type="button" onClick={() => onImport(result)}>
        {`Import ${result.items.length} item(s)`}
      </button>
    </div>
  );
}

export function renderImport(root: HTMLElement, ctx: AppContext): void {
  mount(root, <Import ctx={ctx} />);
}
