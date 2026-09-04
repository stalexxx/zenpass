import { expect, test } from "bun:test";
import { ExtensionSession } from "../src/background.ts";

const request = { pageUrl: "https://example.test/login", isTopFrame: true, formAction: "https://example.test/session", usernameVisible: true, passwordVisible: true };

test("a locked extension refuses before exposing candidates", () => {
  expect(new ExtensionSession().offer(request)).toEqual({ type: "refused", reason: "locked" });
});

test("an unconfirmed fill never exposes selected fields", () => {
  const session = new ExtensionSession();
  session.unlock([{ id: "entry", title: "Entry", origin: "https://example.test", username: "", password: "" }]);
  expect(session.fill(request, "entry", false)).toEqual({ type: "refused", reason: "confirmation-required" });
});

test("lock removes all future offers", () => {
  const session = new ExtensionSession();
  session.unlock([{ id: "entry", title: "Entry", origin: "https://example.test", username: "", password: "" }]);
  session.lock();
  expect(session.offer(request)).toEqual({ type: "refused", reason: "locked" });
});
