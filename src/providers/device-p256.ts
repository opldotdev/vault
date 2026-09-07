import { PassphraseProvider } from './passphrase.js';
import {
  concat,
  fromHexString,
  randomBytes,
  SE_VAULT_HKDF_INFO,
  type SealingProvider,
  toHexString,
} from './provider.js';

function subtle(): SubtleCrypto {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new Error('WebCrypto is not available');
  }
  return crypto.subtle;
}

async function importDevicePublicKey(raw65: Uint8Array): Promise<CryptoKey> {
  return subtle().importKey(
    'raw',
    raw65 as BufferSource,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    [],
  );
}

async function deriveKek(sharedX: Uint8Array): Promise<CryptoKey> {
  const base = await subtle().importKey('raw', sharedX as BufferSource, 'HKDF', false, [
    'deriveKey',
  ]);
  return subtle().deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0) as BufferSource,
      info: new TextEncoder().encode(SE_VAULT_HKDF_INFO) as BufferSource,
    },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function eciesWrap(
  recipientRaw65: Uint8Array,
  contentKey: Uint8Array,
): Promise<Uint8Array> {
  const recipient = await importDevicePublicKey(recipientRaw65);
  const ephemeral = await subtle().generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
    'deriveBits',
  ]);
  const shared = new Uint8Array(
    await subtle().deriveBits(
      { name: 'ECDH', public: recipient },
      ephemeral.privateKey as CryptoKey,
      256,
    ),
  );
  const kek = await deriveKek(shared);
  const nonce = randomBytes(12);
  const sealed = new Uint8Array(
    await subtle().encrypt(
      { name: 'AES-GCM', iv: nonce as BufferSource },
      kek,
      contentKey as BufferSource,
    ),
  );
  const ephemeralPub = new Uint8Array(
    await subtle().exportKey('raw', ephemeral.publicKey as CryptoKey),
  );
  shared.fill(0);
  return concat(ephemeralPub, nonce, sealed);
}

export async function eciesUnwrap(
  devicePrivateKey: CryptoKey,
  wrapped: Uint8Array,
): Promise<Uint8Array> {
  if (wrapped.length < 65 + 12 + 16) throw new Error('wrapped key too short');
  const ephemeralRaw = wrapped.slice(0, 65);
  const nonce = wrapped.slice(65, 77);
  const sealed = wrapped.slice(77);
  const ephemeralPub = await importDevicePublicKey(ephemeralRaw);
  const shared = new Uint8Array(
    await subtle().deriveBits({ name: 'ECDH', public: ephemeralPub }, devicePrivateKey, 256),
  );
  const kek = await deriveKek(shared);
  const plain = await subtle().decrypt(
    { name: 'AES-GCM', iv: nonce as BufferSource },
    kek,
    sealed as BufferSource,
  );
  shared.fill(0);
  return new Uint8Array(plain);
}

export class DeviceKeyProvider implements SealingProvider {
  readonly type = 'device-p256' as const;

  private constructor(
    private readonly devicePrivateKey: CryptoKey,
    private readonly publicKeyHexCache: string,
  ) {}

  static async generate(): Promise<DeviceKeyProvider> {
    const pair = await subtle().generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
      'deriveBits',
    ]);
    const raw = new Uint8Array(await subtle().exportKey('raw', pair.publicKey as CryptoKey));
    return new DeviceKeyProvider(pair.privateKey as CryptoKey, toHexString(raw));
  }

  async exportWrapped(passphrase: string, iterations?: number): Promise<Uint8Array> {
    const jwk = await subtle().exportKey('jwk', this.devicePrivateKey);
    const bytes = new TextEncoder().encode(JSON.stringify(jwk));
    const provider = new PassphraseProvider(passphrase, iterations);
    return provider.wrap(bytes);
  }

  static async importWrapped(
    wrapped: Uint8Array,
    passphrase: string,
    iterations?: number,
  ): Promise<DeviceKeyProvider> {
    const provider = new PassphraseProvider(passphrase, iterations);
    const bytes = await provider.unwrap(wrapped);
    const jwk = JSON.parse(new TextDecoder().decode(bytes)) as JsonWebKey;
    const privateKey = await subtle().importKey(
      'jwk',
      jwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits'],
    );
    const { d: _d, key_ops: _ops, ...publicJwk } = jwk;
    const publicKey = await subtle().importKey(
      'jwk',
      publicJwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      [],
    );
    const raw = new Uint8Array(await subtle().exportKey('raw', publicKey));
    return new DeviceKeyProvider(privateKey, toHexString(raw));
  }

  isSupported(): boolean {
    return typeof crypto !== 'undefined' && !!crypto.subtle;
  }

  async publicKey(): Promise<string> {
    return this.publicKeyHexCache;
  }

  async wrap(contentKey: Uint8Array): Promise<Uint8Array> {
    return eciesWrap(fromHexString(this.publicKeyHexCache), contentKey);
  }

  async unwrap(wrapped: Uint8Array): Promise<Uint8Array> {
    return eciesUnwrap(this.devicePrivateKey, wrapped);
  }
}
