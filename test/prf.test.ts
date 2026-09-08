import { describe, expect, test } from 'bun:test';
import {
  assertPrfCredential,
  PrfProvider,
  prfOutputFromCredential,
  registerPrfCredential,
} from '../src/providers/prf.js';

function bytes(fill: number): Uint8Array {
  return new Uint8Array(32).fill(fill);
}

/** Read the requested `prf.eval.first` input out of a WebAuthn options object. */
function evalFirst(options: unknown): Uint8Array | undefined {
  const first = (
    options as { publicKey?: { extensions?: { prf?: { eval?: { first?: unknown } } } } }
  )?.publicKey?.extensions?.prf?.eval?.first;
  if (first instanceof Uint8Array) return Uint8Array.from(first);
  if (first instanceof ArrayBuffer) return new Uint8Array(first);
  if (ArrayBuffer.isView(first)) {
    const view = first as ArrayBufferView;
    return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
  }
  return undefined;
}

function echoCredential(first: Uint8Array): unknown {
  const out = Uint8Array.from(first);
  return {
    rawId: Uint8Array.from([1, 2, 3, 4]).buffer as ArrayBuffer,
    getClientExtensionResults: () => ({ prf: { results: { first: out.buffer as ArrayBuffer } } }),
  };
}

/** Fake `navigator.credentials`: echoes the requested eval salt back as the PRF output. */
function echoCredentials(): {
  create: (o: unknown) => Promise<unknown>;
  get: (o: unknown) => Promise<unknown>;
} {
  return {
    create: async (options: unknown) => echoCredential(evalFirst(options) ?? bytes(1)),
    get: async (options: unknown) => echoCredential(evalFirst(options) ?? bytes(1)),
  };
}

function missingPrfCredentials(): {
  create: (o: unknown) => Promise<unknown>;
  get: (o: unknown) => Promise<unknown>;
} {
  const cred = {
    rawId: Uint8Array.from([9]).buffer as ArrayBuffer,
    getClientExtensionResults: () => ({}),
  };
  return { create: async () => cred, get: async () => cred };
}

describe('prf provider', () => {
  test('wrap/unwrap round trip via a fake credentials object', async () => {
    const credentials = echoCredentials();
    const salt = bytes(7);
    const provider = await PrfProvider.register(credentials as never, salt);
    expect(provider.type).toBe('prf');
    expect(provider.isSupported()).toBe(true);
    expect(provider.metadata.credentialId).toBe('01020304');
    expect(provider.metadata.prfSalt).toBe(
      '0707070707070707070707070707070707070707070707070707070707070707',
    );

    const contentKey = bytes(42);
    const wrapped = await provider.wrap(contentKey);
    // iv(12) || ct(32) || tag(16)
    expect(wrapped.length).toBe(12 + 32 + 16);
    const back = await provider.unwrap(wrapped);
    expect(Array.from(back)).toEqual(Array.from(contentKey));

    // A fresh assertion ceremony with the same salt reopens the same blob.
    const reopened = await PrfProvider.assert(
      credentials as never,
      provider.credentialId,
      provider.prfSalt,
    );
    const back2 = await reopened.unwrap(wrapped);
    expect(Array.from(back2)).toEqual(Array.from(contentKey));
  });

  test('different salt gives different KEK', async () => {
    const credentials = echoCredentials();
    const a = await PrfProvider.register(credentials as never, bytes(1));
    const b = await PrfProvider.register(credentials as never, bytes(2));
    const contentKey = bytes(9);
    const wrappedA = await a.wrap(contentKey);
    const wrappedB = await b.wrap(contentKey);
    expect(Array.from(wrappedA)).not.toEqual(Array.from(wrappedB));
    // Cross-unwrap with the wrong salt's KEK fails.
    await expect(b.unwrap(wrappedA)).rejects.toThrow();
    await expect(a.unwrap(wrappedB)).rejects.toThrow();

    const outA = await assertPrfCredential(credentials as never, a.credentialId, bytes(1));
    const outB = await assertPrfCredential(credentials as never, b.credentialId, bytes(2));
    expect(Array.from(outA)).not.toEqual(Array.from(outB));
  });

  test('missing PRF extension result throws', async () => {
    const credentials = missingPrfCredentials();
    await expect(registerPrfCredential(credentials as never, bytes(1))).rejects.toThrow(
      'PRF extension result missing',
    );
    await expect(
      assertPrfCredential(credentials as never, new Uint8Array([9]), bytes(1)),
    ).rejects.toThrow('PRF extension result missing');
    expect(() => prfOutputFromCredential({ getClientExtensionResults: () => ({}) })).toThrow(
      'PRF extension result missing',
    );
  });
});
