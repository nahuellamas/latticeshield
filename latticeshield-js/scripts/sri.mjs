#!/usr/bin/env node
// scripts/sri.mjs — Computes SRI hash (sha384) for latticeshield_wasm_bg.wasm
// Runs automatically as postbuild. Output: <wasm-file>.sha384 next to the wasm.
//
// Skips gracefully when the wasm file is not present (e.g. CI npm publish jobs
// that don't run wasm-pack). The SRI hash is for self-hosting users who serve
// the wasm themselves; CI publishes only the JS, so missing wasm here is expected.

import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

const wasmPath = join(__dirname, '../../latticeshield-wasm/pkg/latticeshield_wasm_bg.wasm');
const outPath = wasmPath + '.sha384';

if (!existsSync(wasmPath)) {
  console.warn(`[sri] wasm not built at ${wasmPath} — skipping SRI hash (run wasm-pack build first if you need this)`);
  process.exit(0);
}

const bytes = readFileSync(wasmPath);
const hash = createHash('sha384').update(bytes).digest('base64');
const sri = `sha384-${hash}`;

writeFileSync(outPath, sri, 'utf8');
console.log(`[sri] ${sri}`);
console.log(`[sri] written → ${outPath}`);
