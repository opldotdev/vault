import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { SealingProvider } from './provider.js';

interface HelperOutput {
  success: boolean;
  data?: string;
  error?: string;
  meta?: Record<string, string>;
}

function helperDir(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [resolve(here, '../../swift'), resolve(here, '../swift')];
  for (const dir of candidates) {
    if (existsSync(join(dir, 'build.sh'))) return dir;
  }
  return candidates[0];
}

export function enclaveBinaryPath(): string {
  return join(helperDir(), 'enclave');
}

export function enclaveBuildScript(): string {
  return join(helperDir(), 'build.sh');
}

function ensureBinary(): string {
  const binary = enclaveBinaryPath();
  if (!existsSync(binary)) {
    const script = enclaveBuildScript();
    const result = spawnSync(script, [], { encoding: 'utf8' });
    if (result.error) {
      throw new Error(`enclave build failed: ${(result.error as Error).message}`);
    }
    if (result.status !== 0 || !existsSync(binary)) {
      throw new Error(`enclave binary unavailable: ${result.stderr || 'build failed'}`);
    }
  }
  return binary;
}

function runHelper(args: string[], stdin?: string): HelperOutput {
  const binary = ensureBinary();
  const result = spawnSync(binary, args, {
    input: stdin,
    encoding: 'utf8',
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  if (result.error) throw result.error;
  const stdout = (result.stdout as string).trim();
  try {
    return JSON.parse(stdout) as HelperOutput;
  } catch {
    throw new Error(`enclave helper returned invalid JSON: ${stdout}`);
  }
}

export function isEnclaveSupported(): boolean {
  return process.platform === 'darwin' && process.arch === 'arm64';
}

export class EnclaveProvider implements SealingProvider {
  readonly type = 'enclave' as const;

  constructor(private readonly label = 'vault') {}

  isSupported(): boolean {
    return isEnclaveSupported();
  }

  private requireSupported(): void {
    if (!this.isSupported()) throw new Error('Secure Enclave is not supported on this platform');
  }

  async publicKey(): Promise<string> {
    this.requireSupported();
    const listed = runHelper(['list']);
    if (!listed.success) throw new Error(listed.error || 'enclave list failed');
    const items = JSON.parse(listed.data || '[]') as Array<{ label: string; publicKey: string }>;
    const found = items.find((i) => i.label === this.label);
    if (found) return found.publicKey;
    const generated = runHelper(['generate', this.label]);
    if (!generated.success || !generated.data) {
      throw new Error(generated.error || 'enclave generate failed');
    }
    return generated.data;
  }

  async wrap(contentKey: Uint8Array): Promise<Uint8Array> {
    this.requireSupported();
    await this.publicKey();
    const plaintext = Buffer.from(contentKey).toString('base64');
    const out = runHelper(['encrypt', this.label], plaintext);
    if (!out.success || !out.data) throw new Error(out.error || 'enclave encrypt failed');
    return Uint8Array.from(Buffer.from(out.data, 'base64'));
  }

  async unwrap(wrapped: Uint8Array): Promise<Uint8Array> {
    this.requireSupported();
    const b64 = Buffer.from(wrapped).toString('base64');
    const out = runHelper(['decrypt', this.label, b64, 'Vault']);
    if (!out.success || !out.data) throw new Error(out.error || 'enclave decrypt failed');
    return Uint8Array.from(Buffer.from(out.data, 'base64'));
  }
}
