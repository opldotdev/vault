import { describe, expect, test } from 'bun:test';
import { HD, Mnemonic, PrivateKey } from '@bsv/sdk';
import {
  BRC157_PHRASE,
  bip32Derive,
  brc42Derive,
  brc157IdentityKey,
  brc157Profile,
  brc157Root,
  bytesToHex,
  entropyToMnemonic,
  hexToBytes,
  mnemonicToEntropy,
  throwIfType42,
} from '../src/derive.js';

describe('derive', () => {
  test('BRC-157 phrase round-trips to its entropy', () => {
    const entropy = mnemonicToEntropy(BRC157_PHRASE);
    expect(entropyToMnemonic(entropy)).toBe(BRC157_PHRASE);
    expect(entropy).toBe(bytesToHex(Mnemonic.fromString(BRC157_PHRASE).toEntropy()));
  });

  test('brc157Root produces a valid key and a 33-byte identity key', () => {
    const entropy = mnemonicToEntropy(BRC157_PHRASE);
    const root = brc157Root(entropy);
    expect(root.isValid()).toBe(true);
    const identity = brc157IdentityKey(entropy);
    expect(identity).toHaveLength(66);
    expect(Buffer.from(identity, 'hex')).toHaveLength(33);
    expect(identity).toBe(root.toPublicKey().encode(true, 'hex'));
  });

  test('brc157Profile(1) differs from profile 0', () => {
    const entropy = mnemonicToEntropy(BRC157_PHRASE);
    const p0 = brc157Profile(entropy, 0).toHex();
    const p1 = brc157Profile(entropy, 1).toHex();
    expect(p0).not.toBe(p1);
    expect(brc157Root(entropy).toHex()).toBe(p0);
  });

  test("m/0'/0 differs from m/0'/0'", () => {
    const entropy = mnemonicToEntropy(BRC157_PHRASE);
    const seed = Mnemonic.fromEntropy(hexToBytes(entropy)).toSeed();
    const hardened = HD.fromSeed(seed).derive("m/0'/0'").privKey.toHex();
    const unhardened = HD.fromSeed(seed).derive("m/0'/0").privKey.toHex();
    expect(hardened).not.toBe(unhardened);
  });

  test('rejects zero entropy and bad word counts', () => {
    expect(() => entropyToMnemonic('00'.repeat(32))).toThrow();
    expect(() => entropyToMnemonic('zz')).toThrow();
    expect(() => mnemonicToEntropy('abandon '.repeat(11).trim())).toThrow();
    expect(() => mnemonicToEntropy(`${BRC157_PHRASE} extra`)).toThrow();
  });

  test('bip32Derive derives a child xprv', () => {
    const entropy = mnemonicToEntropy(BRC157_PHRASE);
    const master = HD.fromSeed(Mnemonic.fromEntropy(hexToBytes(entropy)).toSeed());
    const xprv = master.toString();
    const child = bip32Derive(xprv, 'm/0/1');
    expect(child).not.toBe(xprv);
    expect(HD.fromString(child).privKey.isValid()).toBe(true);
  });

  test('brc42Derive derives via KeyDeriver', () => {
    const wif = PrivateKey.fromRandom().toWif();
    const child = brc42Derive(wif, [2, 'vault test'], 'key-1', 'self');
    expect(child.isValid()).toBe(true);
    const other = brc42Derive(wif, [2, 'vault test'], 'key-2', 'self');
    expect(child.toHex()).not.toBe(other.toHex());
  });

  test('type42 throws unsupported', () => {
    expect(() => throwIfType42('type42')).toThrow('unsupported in this version');
    expect(() => throwIfType42('brc42')).not.toThrow();
  });
});
