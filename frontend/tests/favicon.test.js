import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

// Tests de la favicon (lancés avec `node --test`)
const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const faviconPath = join(root, 'static', 'favicon.svg');
const appHtmlPath = join(root, 'src', 'app.html');

test('la favicon SVG existe', () => {
  assert.ok(existsSync(faviconPath), 'static/favicon.svg doit exister');
});

test('la favicon est un SVG valide et non vide', () => {
  const svg = readFileSync(faviconPath, 'utf8').trim();
  assert.ok(svg.length > 0, 'le fichier favicon ne doit pas être vide');
  assert.match(svg, /<svg[\s>]/, 'le fichier doit contenir une balise <svg>');
  assert.match(svg, /<\/svg>\s*$/, 'le fichier doit se terminer par </svg>');
});

test('app.html référence la favicon SVG', () => {
  const html = readFileSync(appHtmlPath, 'utf8');
  assert.match(
    html,
    /<link[^>]+rel="icon"[^>]+favicon\.svg/,
    'app.html doit déclarer <link rel="icon"> pointant vers favicon.svg'
  );
});
