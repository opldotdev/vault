import { concat, randomBytes, type SealingProvider, toHexString } from './provider.js';

// NOTE: persisting PRF-wrapped vault keys needs a dedicated 'prf' slot type in
// the bitcoin-backup envelope (carrying credentialId + prfSalt metadata below).
// That envelope wiring is a separate change; this unit delivers the provider
// and storage only, and src/store.ts is intentionally untouched.

/** HKDF info string for the AES-256-GCM KEK derived from a WebAuthn PRF output. */
export const PRF_HKDF_INFO = 'opl-vault-prf-v1';

const IV_BYTES = 12;

/** Minimal shape of `navigator.credentials` needed by the helpers below. */
export type PrfCredentialsContainer = Pick<CredentialsContainer, 'create' | 'get'>;

export interface PrfRegistration {
  credentialId: Uint8Array;
  prfOutput: Uint8Array;
}

export interface PrfSlotMetadata {
  credentialId: string;
  prfSalt: string;
}

function subtle(): SubtleCrypto {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new Error('WebCrypto is not available');
  }
  return crypto.subtle;
}

function coerceBytes(value: unknown, what: string): Uint8Array {
  if (value instanceof Uint8Array) return Uint8Array.from(value);
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) {
    const view = value as ArrayBufferView;
    return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
  }
  throw new Error(what);
}

/** Extract the `prf.results.first` output from a WebAuthn credential. Throws when absent. */
export function prfOutputFromCredential(credential: unknown): Uint8Array {
  const cred = credential as {
    getClientExtensionResults?: () => unknown;
  };
  if (typeof cred?.getClientExtensionResults !== 'function') {
    throw new Error('PRF extension result missing');
  }
  const results = cred.getClientExtensionResults() as {
    prf?: { results?: { first?: unknown } };
  };
  const first = results?.prf?.results?.first;
  if (first === undefined || first === null) {
    throw new Error('PRF extension result missing');
  }
  return coerceBytes(first, 'PRF extension result missing');
}

function credentialRawId(credential: unknown): Uint8Array {
  const cred = credential as { rawId?: unknown };
  return coerceBytes(cred.rawId, 'credential has no rawId');
}

/** Derive the AES-256-GCM KEK: HKDF-SHA256(prfOutput, salt empty, info PRF_HKDF_INFO). */
export async function derivePrfKek(prfOutput: Uint8Array): Promise<CryptoKey> {
  const base = await subtle().importKey('raw', prfOutput as BufferSource, 'HKDF', false, [
    'deriveKey',
  ]);
  return subtle().deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0) as BufferSource,
      info: new TextEncoder().encode(PRF_HKDF_INFO) as BufferSource,
    },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/** Seal a content key: returns iv(12) || ct || tag. */
export async function prfWrapKey(
  prfOutput: Uint8Array,
  contentKey: Uint8Array,
): Promise<Uint8Array> {
  const kek = await derivePrfKek(prfOutput);
  const iv = randomBytes(IV_BYTES);
  const sealed = new Uint8Array(
    await subtle().encrypt(
      { name: 'AES-GCM', iv: iv as BufferSource },
      kek,
      contentKey as BufferSource,
    ),
  );
  return concat(iv, sealed);
}

/** Open a `prfWrapKey` blob. */
export async function prfUnwrapKey(
  prfOutput: Uint8Array,
  wrapped: Uint8Array,
): Promise<Uint8Array> {
  if (wrapped.length < IV_BYTES + 16) throw new Error('wrapped key too short');
  const iv = wrapped.slice(0, IV_BYTES);
  const sealed = wrapped.slice(IV_BYTES);
  const kek = await derivePrfKek(prfOutput);
  const plain = await subtle().decrypt(
    { name: 'AES-GCM', iv: iv as BufferSource },
    kek,
    sealed as BufferSource,
  );
  return new Uint8Array(plain);
}

/**
 * Register a new WebAuthn credential with PRF evaluation over `prfSalt`.
 * Takes the `navigator.credentials`-shaped object as a parameter for testability.
 */
export async function registerPrfCredential(
  credentials: PrfCredentialsContainer,
  prfSalt: Uint8Array,
  options: { rpName?: string; userName?: string } = {},
): Promise<PrfRegistration> {
  const challenge = randomBytes(32);
  const userId = randomBytes(16);
  const name = options.userName ?? 'vault';
  const credential = (await credentials.create({
    publicKey: {
      challenge: challenge as BufferSource,
      rp: { name: options.rpName ?? 'opl-vault' },
      user: { id: userId as BufferSource, name, displayName: name },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 },
      ],
      authenticatorSelection: { userVerification: 'preferred' },
      extensions: { prf: { eval: { first: prfSalt as BufferSource } } },
    } as PublicKeyCredentialCreationOptions,
  } as never)) as unknown;
  return {
    credentialId: credentialRawId(credential),
    prfOutput: prfOutputFromCredential(credential),
  };
}

/**
 * Run a PRF assertion against `credentialId` with evaluation over `prfSalt`.
 * Takes the `navigator.credentials`-shaped object as a parameter for testability.
 */
export async function assertPrfCredential(
  credentials: PrfCredentialsContainer,
  credentialId: Uint8Array,
  prfSalt: Uint8Array,
): Promise<Uint8Array> {
  const challenge = randomBytes(32);
  const credential = (await credentials.get({
    publicKey: {
      challenge: challenge as BufferSource,
      allowCredentials: [{ id: credentialId as BufferSource, type: 'public-key' }],
      userVerification: 'preferred',
      extensions: { prf: { eval: { first: prfSalt as BufferSource } } },
    } as PublicKeyCredentialRequestOptions,
  } as never)) as unknown;
  return prfOutputFromCredential(credential);
}

/**
 * WebAuthn PRF sealing provider. Holds the credential id, the PRF salt used,
 * and the PRF output from registration/assertion; `wrap` derives the KEK via
 * HKDF-SHA256(prfOutput, salt empty, info 'opl-vault-prf-v1') and seals with
 * AES-256-GCM (`wrapped = iv(12) || ct || tag`).
 */
export class PrfProvider implements SealingProvider {
  readonly type = 'prf' as const;

  constructor(
    readonly credentialId: Uint8Array,
    readonly prfSalt: Uint8Array,
    private readonly prfOutput: Uint8Array,
  ) {
    if (credentialId.length === 0) throw new Error('credential id is empty');
    if (prfOutput.length === 0) throw new Error('PRF output is empty');
  }

  /** Slot metadata for envelope storage: hex-encoded credential id and PRF salt. */
  get metadata(): PrfSlotMetadata {
    return {
      credentialId: toHexString(this.credentialId),
      prfSalt: toHexString(this.prfSalt),
    };
  }

  /** Register a fresh credential and build a provider from the PRF output. */
  static async register(
    credentials: PrfCredentialsContainer,
    prfSalt: Uint8Array = randomBytes(32),
    options?: { rpName?: string; userName?: string },
  ): Promise<PrfProvider> {
    const { credentialId, prfOutput } = await registerPrfCredential(credentials, prfSalt, options);
    return new PrfProvider(credentialId, Uint8Array.from(prfSalt), prfOutput);
  }

  /** Re-run the assertion ceremony and build a provider with the fresh PRF output. */
  static async assert(
    credentials: PrfCredentialsContainer,
    credentialId: Uint8Array,
    prfSalt: Uint8Array,
  ): Promise<PrfProvider> {
    const prfOutput = await assertPrfCredential(credentials, credentialId, prfSalt);
    return new PrfProvider(Uint8Array.from(credentialId), Uint8Array.from(prfSalt), prfOutput);
  }

  isSupported(): boolean {
    return typeof crypto !== 'undefined' && !!crypto.subtle;
  }

  async wrap(contentKey: Uint8Array): Promise<Uint8Array> {
    return prfWrapKey(this.prfOutput, contentKey);
  }

  async unwrap(wrapped: Uint8Array): Promise<Uint8Array> {
    return prfUnwrapKey(this.prfOutput, wrapped);
  }
}
