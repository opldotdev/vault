import { chmod, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import type { Storage } from './memory-storage.js';

const LOCK_STALE_MS = 60_000;

interface LockInfo {
  pid: number;
  at: number;
}

export class FileLocked extends Error {
  constructor(path: string) {
    super(`vault file is locked: ${path}`);
    this.name = 'FileLocked';
  }
}

export class FileStorage implements Storage {
  constructor(readonly path: string) {}

  get lockPath(): string {
    return `${this.path}.lock`;
  }

  async read(): Promise<string | null> {
    try {
      return await readFile(this.path, 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw error;
    }
  }

  async lock(now: () => number = Date.now): Promise<void> {
    const info: LockInfo = { pid: process.pid, at: now() };
    try {
      const raw = await readFile(this.lockPath, 'utf8');
      const existing = JSON.parse(raw) as LockInfo;
      if (typeof existing.at === 'number' && now() - existing.at < LOCK_STALE_MS) {
        throw new FileLocked(this.path);
      }
    } catch (error) {
      if (error instanceof FileLocked) throw error;
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        const corrupt = error instanceof SyntaxError;
        if (!corrupt) throw error;
      }
    }
    await mkdir(dirname(this.path), { recursive: true });
    await writeFile(this.lockPath, JSON.stringify(info), { mode: 0o600 });
  }

  async unlock(): Promise<void> {
    try {
      await rm(this.lockPath, { force: true });
    } catch {
      // lock file already gone
    }
  }

  async withLock<T>(fn: () => Promise<T>, now?: () => number): Promise<T> {
    await this.lock(now);
    try {
      return await fn();
    } finally {
      await this.unlock();
    }
  }

  async write(data: string, now?: () => number): Promise<void> {
    await this.withLock(async () => {
      await mkdir(dirname(this.path), { recursive: true });
      const tmp = join(dirname(this.path), `.vault-tmp-${process.pid}-${Date.now()}`);
      try {
        await writeFile(tmp, data, { mode: 0o600 });
        await chmod(tmp, 0o600);
        await rename(tmp, this.path);
        await chmod(this.path, 0o600);
      } finally {
        await rm(tmp, { force: true });
      }
    }, now);
  }
}
