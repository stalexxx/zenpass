import { createRoot } from "react-dom/client";
import { App, createAppDeps } from "./App.tsx";

const root = document.getElementById("app");
if (!root) throw new Error("missing #app root element");

createAppDeps(root)
  .then((deps) => {
    createRoot(root).render(<App {...deps} />);
  })
  .catch((error) => {
    root.textContent = "Failed to start the app.";
    console.error(error);
  });
