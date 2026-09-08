import { PrivateKey } from '@bsv/sdk';
import { bytesToHex, hexToBytes } from './derive.js';

export function splitEntropy(entropyHex: string, threshold: number, total: number): string[] {
  if (!Number.isInteger(threshold) || !Number.isInteger(total) || threshold < 2 || total < 2) {
    throw new Error('invalid split parameters');
  }
  if (threshold > total) throw new Error('threshold exceeds total');
  const key = PrivateKey.fromHex(bytesToHex(hexToBytes(entropyHex)).padStart(64, '0'));
  return key.toBackupShares(threshold, total);
}

export function recoverEntropy(shares: string[]): string {
  if (!Array.isArray(shares) || shares.length === 0) throw new Error('no shares provided');
  const key = PrivateKey.fromBackupShares(shares);
  return key.toHex().padStart(64, '0');
}
