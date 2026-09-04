import { bootApp } from "./app.ts";

const root = document.getElementById("app");
if (!root) throw new Error("missing #app root element");
bootApp(root).catch((error) => {
  root.textContent = "Failed to start the app.";
  console.error(error);
});
