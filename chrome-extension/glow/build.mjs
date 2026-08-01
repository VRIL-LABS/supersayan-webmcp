import * as esbuild from 'esbuild';
import { readFileSync, copyFileSync, mkdirSync, existsSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const watch = process.argv.includes('--watch');

const baseOptions = {
  bundle: true,
  target: ['chrome120'],
  platform: 'browser',
  format: 'esm',
  outdir: 'dist',
  define: {
    'process.env.NODE_ENV': '"production"',
  },
  alias: {
    '@supersayan/detection-engine': resolve(__dirname, '../../src/lib/supersayan/detection-engine.ts'),
    '@supersayan/defensive-shield': resolve(__dirname, '../../src/lib/supersayan/defensive-shield.ts'),
    '@supersayan/offensive-engine': resolve(__dirname, '../../src/lib/supersayan/offensive-engine.ts'),
    '@supersayan/osint-tracer': resolve(__dirname, '../../src/lib/supersayan/osint-tracer.ts'),
  },
  logLevel: 'info',
};

// Ensure dist directory exists
if (!existsSync('dist')) mkdirSync('dist', { recursive: true });
if (!existsSync('dist/icons')) mkdirSync('dist/icons', { recursive: true });

// Copy static assets
['icons/icon-16.png', 'icons/icon-48.png', 'icons/icon-128.png'].forEach(f => {
  if (existsSync(f)) copyFileSync(f, `dist/${f}`);
});
['popup.html', 'options.html', 'manifest.json'].forEach(f => {
  if (existsSync(f)) copyFileSync(f, `dist/${f}`);
});

// Entrypoints
const entryPoints = [
  { in: 'src/background.ts', out: 'background' },
  { in: 'src/content.ts', out: 'content' },
  { in: 'src/popup.ts', out: 'popup' },
  { in: 'src/options.ts', out: 'options' },
];

if (watch) {
  const ctx = await esbuild.context({ ...baseOptions, entryPoints });
  await ctx.watch();
  console.log('Watching for changes...');
} else {
  await esbuild.build({ ...baseOptions, entryPoints, minify: true });
  console.log('Build complete → dist/');
}
