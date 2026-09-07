import type { Storage } from './memory-storage.js';

const DB_NAME = 'opl-vault';
const STORE_NAME = 'vaults';

function factory(): IDBFactory {
  const candidate = (globalThis as { indexedDB?: IDBFactory }).indexedDB;
  if (!candidate) throw new Error('indexedDB is not available');
  return candidate;
}

function requestToPromise<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('indexedDB request failed'));
  });
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise<IDBDatabase>((resolve, reject) => {
    const request = factory().open(DB_NAME, 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) db.createObjectStore(STORE_NAME);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('indexedDB open failed'));
  });
}

/**
 * Browser vault storage: one record per vault path string in an IndexedDB
 * object store. `lock`/`unlock` are no-ops (single-tab callers serialize
 * writes); `withLock` just runs the callback.
 */
export class IndexedDbStorage implements Storage {
  constructor(readonly path: string) {}

  async read(): Promise<string | null> {
    const db = await openDatabase();
    try {
      const store = db.transaction(STORE_NAME, 'readonly').objectStore(STORE_NAME);
      const value = await requestToPromise<string | undefined>(store.get(this.path));
      return value === undefined ? null : value;
    } finally {
      db.close();
    }
  }

  async write(data: string): Promise<void> {
    const db = await openDatabase();
    try {
      const store = db.transaction(STORE_NAME, 'readwrite').objectStore(STORE_NAME);
      await requestToPromise(store.put(data, this.path));
    } finally {
      db.close();
    }
  }

  async lock(): Promise<void> {
    // No cross-tab locking in the browser build.
  }

  async unlock(): Promise<void> {
    // No-op; see `lock`.
  }

  async withLock<T>(fn: () => Promise<T>): Promise<T> {
    return fn();
  }
}
