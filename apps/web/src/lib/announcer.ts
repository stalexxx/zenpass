// A single shared aria-live region (docs/ux/flows.md: "expose errors in an
// aria-live region"). politeness "assertive" is used for errors so screen
// readers interrupt to announce them; "polite" for routine status so they
// don't.
export class Announcer {
  private readonly polite: HTMLElement;
  private readonly assertive: HTMLElement;

  constructor(root: HTMLElement) {
    this.polite = document.createElement("div");
    this.polite.setAttribute("aria-live", "polite");
    this.polite.setAttribute("role", "status");
    this.polite.className = "sr-only";
    this.assertive = document.createElement("div");
    this.assertive.setAttribute("aria-live", "assertive");
    this.assertive.setAttribute("role", "alert");
    this.assertive.className = "sr-only";
    root.append(this.polite, this.assertive);
  }

  status(message: string): void {
    this.polite.textContent = "";
    // Force a DOM mutation even for a repeated message so it re-announces.
    requestAnimationFrame(() => { this.polite.textContent = message; });
  }

  error(message: string): void {
    this.assertive.textContent = "";
    requestAnimationFrame(() => { this.assertive.textContent = message; });
  }
}
