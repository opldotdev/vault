import { describe, expect, test } from 'bun:test';
import { DeviceKeyProvider } from '../src/providers/device-p256.js';
import { PassphraseProvider } from '../src/providers/passphrase.js';
import { fromHexString } from '../src/providers/provider.js';

describe('passphrase provider', () => {
  test('wrap/unwrap round trip', async () => {
    const provider = new PassphraseProvider('correct horse battery staple', 10_000);
    expect(provider.isSupported()).toBe(true);
    const contentKey = new Uint8Array(32).fill(7);
    const wrapped = await provider.wrap(contentKey);
    expect(wrapped.length).toBeGreaterThan(16 + 12 + 32);
    const back = await provider.unwrap(wrapped);
    expect(Buffer.from(back).toString('hex')).toBe(Buffer.from(contentKey).toString('hex'));
  });

  test('wrapped layout is salt(16) || iv(12) || ct || tag', async () => {
    const provider = new PassphraseProvider('another passphrase', 10_000);
    const wrapped = await provider.wrap(new Uint8Array(32).fill(1));
    // 16 salt + 12 iv + 32 ct + 16 tag
    expect(wrapped.length).toBe(16 + 12 + 32 + 16);
  });

  test('wrong passphrase fails', async () => {
    const a = new PassphraseProvider('right', 10_000);
    const wrapped = await a.wrap(new Uint8Array(32).fill(1));
    const b = new PassphraseProvider('wrong', 10_000);
    await expect(b.unwrap(wrapped)).rejects.toThrow();
  });

  test('empty passphrase is refused', () => {
    expect(() => new PassphraseProvider('')).toThrow();
  });
});

describe('device-p256 provider', () => {
  test('wrap/unwrap round trip with JWK persistence', async () => {
    const device = await DeviceKeyProvider.generate();
    expect(device.isSupported()).toBe(true);
    const pub = await device.publicKey();
    expect(pub).toHaveLength(130);
    expect(pub.startsWith('04')).toBe(true);

    const contentKey = new Uint8Array(32).fill(9);
    const wrapped = await device.wrap(contentKey);
    // 65 pub + 12 nonce + 32 ct + 16 tag
    expect(wrapped.length).toBe(65 + 12 + 32 + 16);
    const back = await device.unwrap(wrapped);
    expect(Buffer.from(back).toString('hex')).toBe(Buffer.from(contentKey).toString('hex'));

    const stored = await device.exportWrapped('device passphrase', 10_000);
    const restored = await DeviceKeyProvider.importWrapped(stored, 'device passphrase', 10_000);
    expect(await restored.publicKey()).toBe(pub);
    const back2 = await restored.unwrap(wrapped);
    expect(Buffer.from(back2).toString('hex')).toBe(Buffer.from(contentKey).toString('hex'));
  });

  test('provider unwraps a wrap built by an independent ECIES encryptor', async () => {
    const device = await DeviceKeyProvider.generate();
    const pubHex = await device.publicKey();
    const contentKey = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);

    // Independent ECIES encryptor written straight from the documented layout:
    // ephemeral P-256 key, shared = ECDH raw X, KEK = HKDF-SHA256(ikm, salt '',
    // info 'se-vault-v1', 32), AES-256-GCM with random nonce,
    // wrapped = ephPub(65) || nonce(12) || ct || tag(16).
    const recipient = await crypto.subtle.importKey(
      'raw',
      fromHexString(pubHex) as BufferSource,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      [],
    );
    const ephemeral = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
      'deriveBits',
    ]);
    const shared = new Uint8Array(
      await crypto.subtle.deriveBits(
        { name: 'ECDH', public: recipient },
        ephemeral.privateKey as CryptoKey,
        256,
      ),
    );
    const base = await crypto.subtle.importKey('raw', shared as BufferSource, 'HKDF', false, [
      'deriveKey',
    ]);
    const kek = await crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(0) as BufferSource,
        info: new TextEncoder().encode('se-vault-v1') as BufferSource,
      },
      base,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt'],
    );
    const nonce = new Uint8Array(12);
    crypto.getRandomValues(nonce);
    const sealed = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce as BufferSource },
        kek,
        contentKey as BufferSource,
      ),
    );
    const ephPub = new Uint8Array(
      await crypto.subtle.exportKey('raw', ephemeral.publicKey as CryptoKey),
    );
    const wrapped = new Uint8Array(65 + 12 + sealed.length);
    wrapped.set(ephPub, 0);
    wrapped.set(nonce, 65);
    wrapped.set(sealed, 77);

    const back = await device.unwrap(wrapped);
    expect(Buffer.from(back).toString('hex')).toBe(Buffer.from(contentKey).toString('hex'));
  });

  test('provider wrap output has the documented framing and rejects tampering', async () => {
    const device = await DeviceKeyProvider.generate();
    const contentKey = new Uint8Array(32).fill(42);
    const wrapped = await device.wrap(contentKey);
    expect(wrapped[0]).toBe(0x04);
    // 65 pub + 12 nonce + 32 ct + 16 tag
    expect(wrapped.length).toBe(65 + 12 + 32 + 16);
    const tampered = Uint8Array.from(wrapped);
    tampered[tampered.length - 1] ^= 0xff;
    await expect(device.unwrap(tampered)).rejects.toThrow();
  });
});
