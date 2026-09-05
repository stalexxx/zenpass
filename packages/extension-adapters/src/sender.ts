import { parseOrigin } from "../../domain/src/origin.ts";

/**
 * Sender authority separation (ADR-0011 D3): TypeScript unions cannot
 * authenticate a message source. These pure helpers classify a runtime
 * `MessageSender`/port sender as a trusted content script or the trusted
 * popup, using browser-provided identity only. Everything else is
 * untrusted and must be ignored.
 */

export interface RuntimeSender {
  /** Extension id the browser attributes the message to. */
  id?: string;
  /** Browser-provided document URL of the sender. */
  url?: string;
  tab?: { id?: number };
  /** Frame the message originated from; 0 is the top frame. */
  frameId?: number;
  /** Browser-provided stable document identity where supported. */
  documentId?: string;
}

export interface TrustedContentSender {
  tabId: number;
  url: string;
  /** Exact HTTPS origin derived from the browser-provided URL. */
  origin: string;
  /** Browser document identity, or null where the build cannot prove it. */
  documentId: string | null;
}

/** A content sender is trusted only when it is this extension's own script,
 * in the top frame (frameId 0) of an HTTPS document of a real tab. The
 * popup and any external/unknown sender never qualify. */
export function trustedContentSender(sender: RuntimeSender | undefined, ownExtensionId: string): TrustedContentSender | null {
  if (!sender || sender.id !== ownExtensionId) return null;
  const tabId = sender.tab?.id;
  if (typeof tabId !== "number" || !Number.isInteger(tabId) || tabId < 0) return null;
  if (sender.frameId !== 0) return null;
  if (typeof sender.url !== "string") return null;
  const origin = parseOrigin(sender.url);
  if (!origin || origin.scheme !== "https:") return null;
  const documentId = typeof sender.documentId === "string" && sender.documentId.length > 0 && sender.documentId.length <= 128 ? sender.documentId : null;
  return { tabId, url: sender.url, origin: new URL(sender.url).origin, documentId };
}

/** The popup is trusted only when the browser attributes the message to this
 * extension with the exact popup document URL and no content-tab sender. */
export function trustedPopupSender(sender: RuntimeSender | undefined, ownExtensionId: string, popupUrl: string): { url: string } | null {
  if (!sender || sender.id !== ownExtensionId) return null;
  if (sender.tab !== undefined) return null;
  if (sender.url !== popupUrl) return null;
  return { url: sender.url };
}
