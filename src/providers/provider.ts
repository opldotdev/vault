export interface SealingProvider {
  readonly type: 'enclave' | 'device-p256' | 'passphrase' | 'prf';
  isSupported(): boolean;
  publicKey?(): Promise<string>;
  wrap(contentKey: Uint8Array): Promise<Uint8Array>;
  unwrap(wrapped: Uint8Array): Promise<Uint8Array>;
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export function toHexString(bytes: ArrayLike<number>): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
  return out;
}

export function fromHexString(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) throw new Error('invalid hex');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

export const SE_VAULT_HKDF_INFO = 'se-vault-v1';
