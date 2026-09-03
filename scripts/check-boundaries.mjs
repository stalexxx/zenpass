import { existsSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const roots = ['apps', 'packages', 'crates'];
const required = [
  'apps/backend/package.json',
  'apps/extension/package.json',
  'apps/web/package.json',
  'packages/sdk/package.json',
  'crates/crypto-core/Cargo.toml',
];
const missing = required.filter((path) => !existsSync(path));
if (missing.length) {
  console.error(`Missing package boundaries: ${missing.join(', ')}`);
  process.exit(1);
}
for (const root of roots) {
  if (!existsSync(root) || !statSync(root).isDirectory() || !readdirSync(root).length) {
    console.error(`Package root is empty or missing: ${root}`);
    process.exit(1);
  }
}
console.log('Package boundaries are valid.');
