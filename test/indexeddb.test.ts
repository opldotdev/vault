import { beforeEach, describe, expect, test } from 'bun:test';
import { IndexedDbStorage } from '../src/storage/indexeddb.js';

// Minimal in-memory fake of indexedDB: just open, objectStore get/put, and close.
class FakeRequest<T> {
  result!: T;
  error: unknown = null;
  onsuccess: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onupgradeneeded: (() => void) | null = null;
}

const tables = new Map<string, Map<unknown, unknown>>();

class FakeObjectStore {
  constructor(private readonly table: Map<unknown, unknown>) {}

  get(key: unknown): FakeRequest<unknown> {
    const request = new FakeRequest<unknown>();
    setTimeout(() => {
      request.result = this.table.has(key) ? this.table.get(key) : undefined;
      request.onsuccess?.();
    }, 0);
    return request;
  }

  put(value: unknown, key: unknown): FakeRequest<unknown> {
    const request = new FakeRequest<unknown>();
    setTimeout(() => {
      this.table.set(key, value);
      request.result = key;
      request.onsuccess?.();
    }, 0);
    return request;
  }
}

class FakeDatabase {
  objectStoreNames = { contains: (name: string) => tables.has(name) };

  createObjectStore(name: string): void {
    if (!tables.has(name)) tables.set(name, new Map());
  }

  transaction(name: string, _mode: string): { objectStore: (n: string) => FakeObjectStore } {
    let table = tables.get(name);
    if (!table) {
      table = new Map();
      tables.set(name, table);
    }
    const resolved = table;
    return { objectStore: () => new FakeObjectStore(resolved) };
  }

  close(): void {}
}

const fakeIndexedDB = {
  open(_name: string, _version: number): FakeRequest<FakeDatabase> {
    const request = new FakeRequest<FakeDatabase>();
    setTimeout(() => {
      request.result = new FakeDatabase();
      request.onupgradeneeded?.();
      request.onsuccess?.();
    }, 0);
    return request;
  },
};

(globalThis as Record<string, unknown>).indexedDB = fakeIndexedDB;

beforeEach(() => {
  tables.clear();
});

describe('indexeddb storage', () => {
  test('read/write round trip', async () => {
    const storage = new IndexedDbStorage('vault/main');
    expect(await storage.read()).toBe(null);
    await storage.write('{"a":1}');
    expect(await storage.read()).toBe('{"a":1}');
  });

  test('records are keyed by vault path', async () => {
    const a = new IndexedDbStorage('vault/a');
    const b = new IndexedDbStorage('vault/b');
    await a.write('aaa');
    expect(await a.read()).toBe('aaa');
    expect(await b.read()).toBe(null);
    await b.write('bbb');
    expect(await a.read()).toBe('aaa');
    expect(await b.read()).toBe('bbb');
  });

  test('write overwrites and lock is a no-op', async () => {
    const storage = new IndexedDbStorage('vault/main');
    await storage.write('first');
    await storage.write('second');
    expect(await storage.read()).toBe('second');
    await expect(storage.lock()).resolves.toBeUndefined();
    await expect(storage.unlock()).resolves.toBeUndefined();
    await expect(storage.withLock(async () => 'ok')).resolves.toBe('ok');
  });
});
