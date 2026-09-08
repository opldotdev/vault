import { describe, expect, test } from 'bun:test';
import { PrivateKey, PublicKey, Signature } from '@bsv/sdk';
import { createSigner, SessionExpired } from '../src/signer.js';

const PROTOCOL: [2, string] = [2, 'vault test'];

describe('signer', () => {
  test('signs and verifies with the bare key', async () => {
    const key = PrivateKey.fromRandom();
    const signer = createSigner(key, { expiresAt: Date.now() + 60_000 });
    const pub = PublicKey.fromString(signer.publicKey());
    const data = new TextEncoder().encode('hello vault');
    const sig = await signer.sign(data);
    expect(pub.verify(Array.from(data), Signature.fromDER(Array.from(sig)))).toBe(true);
  });

  test('encrypts and decrypts round-trip', async () => {
    const key = PrivateKey.fromRandom();
    const signer = createSigner(key, { expiresAt: Date.now() + 60_000 });
    const data = new TextEncoder().encode('secret message');
    const ct = await signer.encrypt(data, PROTOCOL, 'k1', 'self');
    const pt = await signer.decrypt(ct, PROTOCOL, 'k1', 'self');
    expect(new TextDecoder().decode(pt)).toBe('secret message');
  });

  test('derived public key matches derived private key', async () => {
    const key = PrivateKey.fromRandom();
    const signer = createSigner(key, { expiresAt: Date.now() + 60_000 });
    const derivedPub = signer.derivedPublicKey(PROTOCOL, 'k1', 'self');
    expect(derivedPub).toHaveLength(66);
    const data = new TextEncoder().encode('derived signing');
    const sig = await signer.sign(data, PROTOCOL, 'k1', 'self');
    const pub = PublicKey.fromString(derivedPub);
    expect(pub.verify(Array.from(data), Signature.fromDER(Array.from(sig)), 'utf8')).toBe(true);
  });

  test('ecdh agrees on both sides', async () => {
    const a = PrivateKey.fromRandom();
    const b = PrivateKey.fromRandom();
    const signerA = createSigner(a, { expiresAt: Date.now() + 60_000 });
    const signerB = createSigner(b, { expiresAt: Date.now() + 60_000 });
    const secretA = await signerA.ecdh(
      b.toPublicKey().encode(true, 'hex') as string,
      PROTOCOL,
      'k',
    );
    const secretB = await signerB.ecdh(
      a.toPublicKey().encode(true, 'hex') as string,
      PROTOCOL,
      'k',
    );
    expect(Buffer.from(secretA).toString('hex')).toBe(Buffer.from(secretB).toString('hex'));
    expect(secretA).toHaveLength(32);
  });

  test('holds the key in a closure', () => {
    const key = PrivateKey.fromRandom();
    const wif = key.toWif();
    const hex = key.toHex().padStart(64, '0');
    const signer = createSigner(key, { expiresAt: Date.now() + 60_000 });
    const dumped = JSON.stringify(signer);
    expect(dumped).not.toContain(wif);
    expect(dumped).not.toContain(hex);
    for (const value of Object.values(signer as unknown as Record<string, unknown>)) {
      expect(value).not.toBeInstanceOf(PrivateKey);
    }
    expect('privateKey' in (signer as object)).toBe(false);
  });

  test('every method throws SessionExpired after expiry', async () => {
    const key = PrivateKey.fromRandom();
    const signer = createSigner(key, { expiresAt: Date.now() - 1 });
    expect(() => signer.publicKey()).toThrow(SessionExpired);
    expect(() => signer.derivedPublicKey(PROTOCOL, 'k', 'self')).toThrow(SessionExpired);
    const data = new Uint8Array([1, 2, 3]);
    await expect(signer.sign(data)).rejects.toThrow(SessionExpired);
    await expect(signer.encrypt(data, PROTOCOL, 'k', 'self')).rejects.toThrow(SessionExpired);
    await expect(signer.decrypt(data, PROTOCOL, 'k', 'self')).rejects.toThrow(SessionExpired);
    await expect(
      signer.ecdh(key.toPublicKey().encode(true, 'hex') as string, PROTOCOL, 'k'),
    ).rejects.toThrow(SessionExpired);
  });
});
