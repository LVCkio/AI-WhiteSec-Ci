import { copyFile, mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const project = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const packages = resolve(project, '.dashboard-build/node_modules');
const target = resolve(project, 'app/static/dashboard/vendor');
await mkdir(target, { recursive: true });
const files = [
  ['lucide/dist/umd/lucide.min.js', 'lucide.min.js'],
  ['lucide/LICENSE', 'lucide.LICENSE'],
  ['@fontsource-variable/inter/LICENSE', 'inter.LICENSE'],
  ['@fontsource/jetbrains-mono/LICENSE', 'jetbrains-mono.LICENSE'],
  ...['latin', 'latin-ext', 'vietnamese'].flatMap(subset => [
    [`@fontsource-variable/inter/files/inter-${subset}-wght-normal.woff2`, `inter-${subset}.woff2`],
    [`@fontsource/jetbrains-mono/files/jetbrains-mono-${subset}-400-normal.woff2`, `jetbrains-mono-${subset}.woff2`],
  ]),
];
for (const [source, destination] of files) await copyFile(resolve(packages, source), resolve(target, destination));
console.log(`Prepared ${files.length} local dashboard assets.`);
