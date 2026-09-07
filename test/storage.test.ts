import { describe, expect, test } from 'bun:test';
import { mkdtempSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FileLocked, FileStorage } from '../src/storage/file-storage.js';
import { MemoryStorage } from '../src/storage/memory-storage.js';

function tmpPath(): string {
  return join(mkdtempSync(join(tmpdir(), 'vault-storage-')), 'vault.json');
}

describe('memory storage', () => {
  test('read/write round trip', async () => {
    const storage = new MemoryStorage();
    expect(await storage.read()).toBe(null);
    await storage.write('hello');
    expect(await storage.read()).toBe('hello');
  });
});

describe('file storage', () => {
  test('read/write round trip with mode 0600', async () => {
    const path = tmpPath();
    const storage = new FileStorage(path);
    expect(await storage.read()).toBe(null);
    await storage.write('{"a":1}');
    expect(await storage.read()).toBe('{"a":1}');
    expect(statSync(path).mode & 0o777).toBe(0o600);
  });

  test('a failed write leaves the old file', async () => {
    const path = tmpPath();
    const storage = new FileStorage(path);
    await storage.write('original');
    // Hold a fresh lock so the next write cannot proceed.
    await storage.lock();
    try {
      await expect(storage.write('replacement')).rejects.toThrow(FileLocked);
    } finally {
      await storage.unlock();
    }
    expect(await storage.read()).toBe('original');
    expect(readFileSync(path, 'utf8')).toBe('original');
  });

  test('locking blocks a second locker and stale locks expire', async () => {
    const path = tmpPath();
    const a = new FileStorage(path);
    const b = new FileStorage(path);
    await a.lock();
    await expect(b.lock()).rejects.toThrow(FileLocked);
    await a.unlock();
    await b.lock();
    await b.unlock();
    // Stale lock (older than 60 s) does not block.
    await a.lock(() => Date.now() - 61_000);
    await expect(b.lock()).resolves.toBeUndefined();
    await b.unlock();
  });
});
