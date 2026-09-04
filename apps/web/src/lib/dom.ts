// Minimal DOM-construction helper (no framework — see the completion
// report for the zero-dependency-UI-framework decision). `h(tag, props,
// children)` mirrors the shape of hyperscript/JSX without a build-time
// transform.
type Props = Record<string, unknown>;
type Child = Node | string | null | undefined | false;

export function h(tag: string, props: Props = {}, ...children: Child[]): HTMLElement {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (key.startsWith("on") && typeof value === "function") {
      el.addEventListener(key.slice(2).toLowerCase(), value as EventListener);
    } else if (key === "class") {
      el.className = String(value);
    } else if (key === "value" && "value" in el) {
      (el as HTMLInputElement).value = String(value);
    } else if (key === "checked" && "checked" in el) {
      (el as HTMLInputElement).checked = Boolean(value);
    } else if (key === "html") {
      el.innerHTML = String(value);
    } else if (typeof value === "boolean") {
      if (value) el.setAttribute(key, "");
    } else {
      el.setAttribute(key, String(value));
    }
  }
  for (const child of children.flat(Infinity as 1)) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

export function clear(el: Element): void {
  while (el.firstChild) el.removeChild(el.firstChild);
}

export function mount(root: Element, node: Node): void {
  clear(root);
  root.append(node);
}
