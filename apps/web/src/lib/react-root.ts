// Shared React root cache so the imperative `renderX(container, ...)`
// entry points used by tests (and any other non-App caller) can safely
// hand off the same DOM container between different view components
// without React's "createRoot() called twice on the same container"
// warning. Mirrors the old lib/dom.ts `mount()` helper's one job — replace
// a container's contents with a fresh tree — but through React's root API
// instead of raw DOM clearing.
import { createRoot, type Root } from "react-dom/client";
import { flushSync } from "react-dom";
import type { ReactElement } from "react";

const roots = new WeakMap<Element, Root>();

/** `flushSync` forces this render (and the initial mount) to commit
 * synchronously, matching the old hand-rolled `mount()`'s always-synchronous
 * behavior — React 18+'s concurrent root otherwise schedules even an
 * initial mount through the scheduler, which several existing tests
 * (correctly) don't expect: they assert on the DOM immediately after
 * calling one of these `renderX` entry points, with no `await` in
 * between. */
export function mount(container: Element, element: ReactElement): void {
  let root = roots.get(container);
  if (!root) {
    root = createRoot(container);
    roots.set(container, root);
  }
  const activeRoot = root;
  flushSync(() => {
    activeRoot.render(element);
  });
}
