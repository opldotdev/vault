import { beforeAll, describe, expect, test } from 'bun:test';
import { existsSync, readFileSync } from 'node:fs';

const BROWSER_JS = new URL('../dist/browser.js', import.meta.url).pathname;
const PACKAGE_JSON = new URL('../package.json', import.meta.url).pathname;

beforeAll(async () => {
  if (!existsSync(BROWSER_JS)) {
    const proc = Bun.spawn(['bun', 'run', 'build'], { stdout: 'pipe', stderr: 'pipe' });
    const code = await proc.exited;
    if (code !== 0) {
      const err = await new Response(proc.stderr).text();
      throw new Error(`bun run build failed:\n${err}`);
    }
  }
}, 120_000);

describe('browser build', () => {
  test('dist/browser.js exists and has no platform import specifiers', () => {
    expect(existsSync(BROWSER_JS)).toBe(true);
    const text = readFileSync(BROWSER_JS, 'utf8');
    expect(text.length).toBeGreaterThan(0);
    expect(text).not.toContain('node:');
  });

  test('package.json declares the browser export condition', () => {
    const pkg = JSON.parse(readFileSync(PACKAGE_JSON, 'utf8')) as {
      exports?: {
        '.'?: { browser?: string };
        './browser'?: { types?: string; default?: string };
      };
    };
    expect(pkg.exports?.['.']?.browser).toBe('./dist/browser.js');
    expect(pkg.exports?.['./browser']).toEqual({
      types: './dist/browser.d.ts',
      default: './dist/browser.js',
    });
  });
});
