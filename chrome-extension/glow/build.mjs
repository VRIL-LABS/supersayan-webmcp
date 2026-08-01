/**
 * Glow — esbuild configuration
 *
 * Output format notes:
 *  - background.js: ESM (manifest declares "type": "module")
 *  - content.js:   IIFE (manifest content_scripts has no "type" field — Chrome
 *                  loads it as a classic script, not a module)
 *  - popup.js:     IIFE (<script src="popup.js"> with no type="module")
 *  - options.js:   IIFE (<script src="options.js"> with no type="module")
 */

import * as esbuild from 'esbuild';
import { copyFileSync, mkdirSync, existsSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const isWatch   = process.argv.includes('--watch');
const isRelease = process.argv.includes('--release');

// Path aliases pointing to the supersayan lib in the Next.js project
const alias = {
  '@supersayan/detection-engine': resolve(__dirname, '../../src/lib/supersayan/detection-engine.ts'),
  '@supersayan/defensive-shield': resolve(__dirname, '../../src/lib/supersayan/defensive-shield.ts'),
  '@supersayan/offensive-engine': resolve(__dirname, '../../src/lib/supersayan/offensive-engine.ts'),
  '@supersayan/osint-tracer':     resolve(__dirname, '../../src/lib/supersayan/osint-tracer.ts'),
};

const sharedOptions = {
  bundle:   true,
  target:   ['chrome120'],
  platform: 'browser',
  outdir:   'dist',
  alias,
  define:   { 'process.env.NODE_ENV': '"production"' },
  logLevel: 'info',
  minify:   isRelease,
  sourcemap: !isRelease,
};

// ── Ensure output dirs ─────────────────────────────────────────────────────────
for (const dir of ['dist', 'dist/icons']) {
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
}

// ── Copy static assets ─────────────────────────────────────────────────────────
const statics = [
  'icons/icon-16.png',
  'icons/icon-48.png',
  'icons/icon-128.png',
  'popup.html',
  'options.html',
  'manifest.json',
];
for (const f of statics) {
  if (existsSync(f)) copyFileSync(f, `dist/${f}`);
}

// ── Entrypoints ────────────────────────────────────────────────────────────────
//
// background must be ESM (manifest: "type":"module").
// content, popup, options must be IIFE — no "type":"module" on their script tags.

const esmEntries  = [{ in: 'src/background.ts', out: 'background' }];
const iifeEntries = [
  { in: 'src/content.ts', out: 'content' },
  { in: 'src/popup.ts',   out: 'popup' },
  { in: 'src/options.ts', out: 'options' },
];

if (isWatch) {
  // Run both contexts in parallel watch mode
  const [esmCtx, iifeCtx] = await Promise.all([
    esbuild.context({ ...sharedOptions, format: 'esm',  entryPoints: esmEntries }),
    esbuild.context({ ...sharedOptions, format: 'iife', entryPoints: iifeEntries }),
  ]);
  await Promise.all([esmCtx.watch(), iifeCtx.watch()]);
  console.log('Watching for changes...');
} else {
  await Promise.all([
    esbuild.build({ ...sharedOptions, format: 'esm',  entryPoints: esmEntries }),
    esbuild.build({ ...sharedOptions, format: 'iife', entryPoints: iifeEntries }),
  ]);
  console.log('Build complete \u2192 dist/');
}
