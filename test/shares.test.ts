import { describe, expect, test } from 'bun:test';
import { BRC157_PHRASE, mnemonicToEntropy } from '../src/derive.js';
import { recoverEntropy, splitEntropy } from '../src/shares.js';

describe('shares', () => {
  test('2-of-3 round trip', () => {
    const entropy = mnemonicToEntropy(BRC157_PHRASE);
    const shares = splitEntropy(entropy, 2, 3);
    expect(shares).toHaveLength(3);
    expect(recoverEntropy(shares)).toBe(entropy.padStart(64, '0'));
  });

  test('any two shares recover', () => {
    const entropy = mnemonicToEntropy(BRC157_PHRASE);
    const shares = splitEntropy(entropy, 2, 3);
    const expected = entropy.padStart(64, '0');
    expect(recoverEntropy([shares[0], shares[1]])).toBe(expected);
    expect(recoverEntropy([shares[0], shares[2]])).toBe(expected);
    expect(recoverEntropy([shares[1], shares[2]])).toBe(expected);
  });
});
