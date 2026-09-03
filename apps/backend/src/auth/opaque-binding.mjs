// Loads the generated WASM module from packages/crypto-server (ADR-0006).
// Relative import, matching packages/crypto-worker's convention of
// importing a sibling package's pkg/*.js output directly rather than
// through the workspace bare specifier.
import init, {
  generate_server_setup,
  login_finish,
  login_start,
  registration_step,
} from '../../../../packages/crypto-server/pkg/crypto_server.js';

let ready;

/** Resolves once to a stable binding object; safe to call repeatedly. */
export function loadOpaqueBinding() {
  if (!ready) {
    ready = init().then(() => ({
      generateServerSetup: generate_server_setup,
      registrationStep: registration_step,
      loginStart: login_start,
      loginFinish: login_finish
    }));
  }
  return ready;
}
