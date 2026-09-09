import {
  ARGON2ID_DEFAULTS,
  ARGON2ID_FAST,
  type Argon2idParams,
  assertPassphrase,
  deriveArgon2idKey,
  resolveArgon2idParams,
} from 'bitcoin-backup';
import { concat, randomBytes, type SealingProvider } from './provider.js';

export const DEFAULT_PBKDF2_ITERATIONS = 600_000;
const SALT_BYTES = 16;
const IV_BYTES = 12;
const ARGON2_WRAP_VERSION = 0xa2;

export type PassphraseProviderOptions = {
  argon2?: Partial<Argon2idParams>;
};

function subtle(): SubtleCrypto {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new Error('WebCrypto is not available');
  }
  return crypto.subtle;
}

function u32be(value: number): Uint8Array {
  const out = new Uint8Array(4);
  out[0] = (value >>> 24) & 0xff;
  out[1] = (value >>> 16) & 0xff;
  out[2] = (value >>> 8) & 0xff;
  out[3] = value & 0xff;
  return out;
}

function readU32be(bytes: Uint8Array, offset: number): number {
  return (
    ((bytes[offset] << 24) |
      (bytes[offset + 1] << 16) |
      (bytes[offset + 2] << 8) |
      bytes[offset + 3]) >>>
    0
  );
}

function defaultArgon2(): Argon2idParams {
  if (typeof process !== 'undefined' && process.env?.VAULT_ARGON2_FAST === '1')
    return ARGON2ID_FAST;
  return ARGON2ID_DEFAULTS;
}

async function derivePbkdf2Kek(
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
  readonly argon2: Argon2idParams;

  constructor(
    /** The passphrase; also passed through verbatim to argon2id backup slots by src/store.ts. */
    readonly passphrase: string,
    iterationsOrOptions: number | PassphraseProviderOptions = {},
  ) {
    assertPassphrase(passphrase);
    const options = typeof iterationsOrOptions === 'number' ? {} : (iterationsOrOptions ?? {});
    this.argon2 = resolveArgon2idParams(options.argon2 ?? defaultArgon2());
  }

  isSupported(): boolean {
    return typeof crypto !== 'undefined' && !!crypto.subtle;
  }

  async wrap(contentKey: Uint8Array): Promise<Uint8Array> {
    const salt = randomBytes(SALT_BYTES);
    const iv = randomBytes(IV_BYTES);
    const kek = await deriveArgon2idKey(this.passphrase, salt, this.argon2);
    const sealed = new Uint8Array(
      await subtle().encrypt(
        { name: 'AES-GCM', iv: iv as BufferSource },
        kek,
        contentKey as BufferSource,
      ),
    );
    return concat(
      new Uint8Array([ARGON2_WRAP_VERSION]),
      salt,
      u32be(this.argon2.memoryKiB),
      u32be(this.argon2.iterations),
      u32be(this.argon2.parallelism),
      iv,
      sealed,
    );
  }

  async unwrap(wrapped: Uint8Array): Promise<Uint8Array> {
    if (
      wrapped.length >= 1 + SALT_BYTES + 12 + IV_BYTES + 16 &&
      wrapped[0] === ARGON2_WRAP_VERSION
    ) {
      const salt = wrapped.slice(1, 1 + SALT_BYTES);
      const memoryKiB = readU32be(wrapped, 1 + SALT_BYTES);
      const iterations = readU32be(wrapped, 1 + SALT_BYTES + 4);
      const parallelism = readU32be(wrapped, 1 + SALT_BYTES + 8);
      const ivStart = 1 + SALT_BYTES + 12;
      const iv = wrapped.slice(ivStart, ivStart + IV_BYTES);
      const sealed = wrapped.slice(ivStart + IV_BYTES);
      const kek = await deriveArgon2idKey(this.passphrase, salt, {
        memoryKiB,
        iterations,
        parallelism,
      });
      const plain = await subtle().decrypt(
        { name: 'AES-GCM', iv: iv as BufferSource },
        kek,
        sealed as BufferSource,
      );
      return new Uint8Array(plain);
    }
    if (wrapped.length < SALT_BYTES + IV_BYTES + 16) throw new Error('wrapped key too short');
    const salt = wrapped.slice(0, SALT_BYTES);
    const iv = wrapped.slice(SALT_BYTES, SALT_BYTES + IV_BYTES);
    const sealed = wrapped.slice(SALT_BYTES + IV_BYTES);
    const kek = await derivePbkdf2Kek(this.passphrase, salt, DEFAULT_PBKDF2_ITERATIONS);
    const plain = await subtle().decrypt(
      { name: 'AES-GCM', iv: iv as BufferSource },
      kek,
      sealed as BufferSource,
    );
    return new Uint8Array(plain);
  }
}
