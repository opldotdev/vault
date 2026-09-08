import { afterAll, describe, expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import {
  EnclaveProvider,
  enclaveBinaryPath,
  isEnclaveSupported,
} from '../src/providers/enclave.js';

const MAY_RUN = isEnclaveSupported();
// Decrypt requires a Touch ID prompt; only opt in explicitly.
const MAY_TOUCH = MAY_RUN && process.env.VAULT_TEST_TOUCHID === '1';
const LABEL = `vault-test-${process.pid}`;

afterAll(() => {
  if (MAY_RUN) spawnSync(enclaveBinaryPath(), ['delete', LABEL]);
});

describe('enclave provider', () => {
  test('isSupported matches darwin arm64', () => {
    expect(new EnclaveProvider().isSupported()).toBe(
      process.platform === 'darwin' && process.arch === 'arm64',
    );
  });

  test.skipIf(!MAY_RUN)('publicKey and wrap work without Touch ID', async () => {
    const provider = new EnclaveProvider(LABEL);
    const pub = await provider.publicKey();
    expect(pub).toHaveLength(130);
    expect(pub.startsWith('04')).toBe(true);
    const wrapped = await provider.wrap(new Uint8Array(32).fill(11));
    expect(wrapped.length).toBeGreaterThan(65 + 12 + 16);
  });

  test.skipIf(!MAY_TOUCH)('unwrap round trip (requires Touch ID)', async () => {
    const provider = new EnclaveProvider(LABEL);
    const contentKey = new Uint8Array(32).fill(11);
    const wrapped = await provider.wrap(contentKey);
    const back = await provider.unwrap(wrapped);
    expect(Buffer.from(back).toString('hex')).toBe(Buffer.from(contentKey).toString('hex'));
  });
});
