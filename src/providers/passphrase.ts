import { concat, randomBytes, type SealingProvider } from './provider.js';

export const DEFAULT_PBKDF2_ITERATIONS = 600_000;
const SALT_BYTES = 16;
const IV_BYTES = 12;

function subtle(): SubtleCrypto {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new Error('WebCrypto is not available');
  }
  return crypto.subtle;
}

async function deriveKek(
  passphrase: string,
  salt: Uint8Array,
  iterations: number,
): Promise<CryptoKey> {
  const base = await subtle().importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return subtle().deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt: salt as BufferSource, iterations },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export class PassphraseProvider implements SealingProvider {
  readonly type = 'passphrase' as const;

  constructor(
    private readonly passphrase: string,
    private readonly iterations: number = DEFAULT_PBKDF2_ITERATIONS,
  ) {
    if (passphrase.length === 0) throw new Error('empty passphrase');
  }

  isSupported(): boolean {
    return typeof crypto !== 'undefined' && !!crypto.subtle;
  }

  async wrap(contentKey: Uint8Array): Promise<Uint8Array> {
    const salt = randomBytes(SALT_BYTES);
    const iv = randomBytes(IV_BYTES);
    const kek = await deriveKek(this.passphrase, salt, this.iterations);
    const sealed = new Uint8Array(
      await subtle().encrypt(
        { name: 'AES-GCM', iv: iv as BufferSource },
        kek,
        contentKey as BufferSource,
      ),
    );
    const out = concat(salt, iv, sealed);
    return out;
  }

  async unwrap(wrapped: Uint8Array): Promise<Uint8Array> {
    if (wrapped.length < SALT_BYTES + IV_BYTES + 16) throw new Error('wrapped key too short');
    const salt = wrapped.slice(0, SALT_BYTES);
    const iv = wrapped.slice(SALT_BYTES, SALT_BYTES + IV_BYTES);
    const sealed = wrapped.slice(SALT_BYTES + IV_BYTES);
    const kek = await deriveKek(this.passphrase, salt, this.iterations);
    const plain = await subtle().decrypt(
      { name: 'AES-GCM', iv: iv as BufferSource },
      kek,
      sealed as BufferSource,
    );
    return new Uint8Array(plain);
  }
}
