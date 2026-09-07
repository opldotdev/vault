import { HD, KeyDeriver, Mnemonic, PrivateKey, type PublicKey } from '@bsv/sdk';
import { fromHexString, toHexString } from './providers/provider.js';

const SECP256K1_N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

const WORD_COUNTS = new Set([12, 15, 18, 21, 24]);

export const BRC157_PHRASE =
  'legal winner thank year wave sausage worth useful legal winner thank yellow';

export function hexToBytes(hex: string): number[] {
  if (typeof hex !== 'string') throw new Error('invalid entropy hex');
  return Array.from(fromHexString(hex));
}

export const bytesToHex = toHexString;

function checkScalarRange(bytes: number[]): void {
  const sizes = new Set([16, 20, 24, 28, 32]);
  if (!sizes.has(bytes.length)) throw new Error('invalid entropy length');
  const value = bytes.length === 0 ? 0n : BigInt(`0x${bytesToHex(bytes)}`);
  if (value < 1n || value >= SECP256K1_N) throw new Error('entropy out of range');
}

export function entropyToMnemonic(entropyHex: string): string {
  const bytes = hexToBytes(entropyHex);
  checkScalarRange(bytes);
  return Mnemonic.fromEntropy(bytes).toString();
}

export function mnemonicToEntropy(words: string): string {
  const count = words.trim().split(/\s+/).filter(Boolean).length;
  if (!WORD_COUNTS.has(count)) throw new Error('invalid mnemonic word count');
  const mnemonic = Mnemonic.fromString(words.trim().split(/\s+/).join(' '));
  const entropy = mnemonic.toEntropy();
  checkScalarRange(entropy);
  return bytesToHex(entropy);
}

function seedFromEntropy(entropyHex: string): number[] {
  const bytes = hexToBytes(entropyHex);
  checkScalarRange(bytes);
  return Mnemonic.fromEntropy(bytes).toSeed();
}

export function brc157Root(entropyHex: string): PrivateKey {
  return HD.fromSeed(seedFromEntropy(entropyHex)).derive("m/0'/0'").privKey;
}

export function brc157Profile(entropyHex: string, index: number): PrivateKey {
  if (!Number.isInteger(index) || index < 0) throw new Error('invalid profile index');
  return HD.fromSeed(seedFromEntropy(entropyHex)).derive(`m/0'/${index}'`).privKey;
}

export function brc157IdentityKey(entropyHex: string): string {
  return brc157Root(entropyHex).toPublicKey().encode(true, 'hex') as string;
}

export function privateKeyToHex(key: PrivateKey): string {
  return key.toHex().padStart(64, '0');
}

export function publicKeyHex(key: PrivateKey | PublicKey): string {
  const pub = key instanceof PrivateKey ? key.toPublicKey() : key;
  return pub.encode(true, 'hex') as string;
}

export function bip32Derive(xkey: string, path: string): string {
  return HD.fromString(xkey).derive(path).toString();
}

export type Brc42Protocol = [0 | 1 | 2, string];

/** Explicit BRC-42 parameters; a derivation descriptor alone cannot carry them. */
export interface Brc42Params {
  protocolID: Brc42Protocol;
  keyID: string;
  counterparty?: string;
}

export function brc42Derive(
  rootWif: string,
  protocolID: Brc42Protocol,
  keyID: string,
  counterparty: string,
): PrivateKey {
  const root = PrivateKey.fromWif(rootWif);
  const deriver = new KeyDeriver(root);
  return deriver.derivePrivateKey(protocolID, keyID, counterparty);
}

export function brc42DerivePublicKey(
  rootWif: string,
  protocolID: Brc42Protocol,
  keyID: string,
  counterparty: string,
): string {
  return publicKeyHex(brc42Derive(rootWif, protocolID, keyID, counterparty));
}

export function throwIfType42(scheme: string): void {
  if (scheme === 'type42') throw new Error('unsupported in this version');
}
