import {
  decryptBackup,
  eciesEncrypt,
  inspectEnvelope,
  isEnvelopeV2,
  openBackup,
  sealBackup,
  type Unlock,
  type VaultBackup,
} from 'bitcoin-backup';
import type { Entry } from './document.js';
import { PassphraseProvider } from './providers/passphrase.js';
import type { SealingProvider } from './providers/provider.js';
import { base64Utf8, providerToUnlock, randomSuffix, utf8Base64, VAULT_SCHEME } from './store.js';
import type { Vault } from './vault.js';

/** Scheme marker for a single-entry export envelope payload. */
export const VAULT_ENTRY_SCHEME = 'opl-vault-entry-v1';

export type TransferUnlock = { passphrase: string } | { provider: SealingProvider };

interface SealedEntry {
  entry: Entry;
}

function passphraseOfUnlock(unlock: TransferUnlock): string | null {
  if ('passphrase' in unlock) return unlock.passphrase;
  if (unlock.provider instanceof PassphraseProvider) return unlock.provider.passphrase;
  return null;
}

function isVaultBackup(payload: unknown): payload is VaultBackup {
  return (
    typeof payload === 'object' &&
    payload !== null &&
    typeof (payload as Partial<VaultBackup>).encryptedVault === 'string'
  );
}

function decodeDocumentPayload(payload: VaultBackup): { entries: Entry[]; detail: string } {
  const doc = JSON.parse(utf8Base64(payload.encryptedVault)) as { entries?: Entry[] };
  if (!Array.isArray(doc.entries)) throw new Error('vault payload has no entries');
  return { entries: doc.entries, detail: payload.scheme ?? VAULT_SCHEME };
}

function decodeSingleEntryPayload(payload: VaultBackup): Entry {
  const parsed = JSON.parse(utf8Base64(payload.encryptedVault)) as Partial<SealedEntry>;
  if (typeof parsed !== 'object' || parsed === null || typeof parsed.entry !== 'object') {
    throw new Error('entry payload has no entry');
  }
  return parsed.entry as Entry;
}

/**
 * Open any bitcoin-backup envelope (v1 via `decryptBackup`, v2 via `openBackup`)
 * and import its payload. A `VaultBackup` with scheme `opl-vault-v1` is a foreign
 * vault document: every entry is adopted with a new id (labels, tags, derivation,
 * roles, and metadata kept, one log line per entry). Scheme `opl-vault-entry-v1`
 * is a single entry in the same shape. Anything else routes through
 * `vault.importPlain` with `label`.
 */
export async function importEncrypted(
  vault: Vault,
  bep: string,
  unlock: TransferUnlock,
  label: string,
): Promise<Entry[]> {
  let payload: unknown;
  if (isEnvelopeV2(bep)) {
    const openUnlock: Unlock =
      'passphrase' in unlock
        ? { passphrase: unlock.passphrase }
        : await providerToUnlock(unlock.provider, inspectEnvelope(bep).slots);
    payload = await openBackup(bep, openUnlock);
  } else {
    const passphrase = passphraseOfUnlock(unlock);
    if (passphrase === null) {
      throw new Error('v1 envelopes require a passphrase unlock');
    }
    payload = await decryptBackup(bep, passphrase);
  }
  if (isVaultBackup(payload)) {
    if (payload.scheme === VAULT_SCHEME) {
      const { entries, detail } = decodeDocumentPayload(payload);
      return entries.map((entry) => vault.adoptEntry(entry, detail));
    }
    if (payload.scheme === VAULT_ENTRY_SCHEME) {
      return [vault.adoptEntry(decodeSingleEntryPayload(payload), payload.scheme)];
    }
  }
  return vault.importPlain(payload, label);
}

/**
 * Unwrap a sealed single entry with `provider` (plaintext is UTF-8 JSON
 * `{ entry: Entry }`) and import it with a new id under `label`.
 */
export async function importSealed(
  vault: Vault,
  wrapped: Uint8Array,
  provider: SealingProvider,
  label: string,
): Promise<Entry> {
  const plain = await provider.unwrap(wrapped);
  const parsed = JSON.parse(new TextDecoder().decode(plain)) as Partial<SealedEntry>;
  if (typeof parsed !== 'object' || parsed === null || typeof parsed.entry !== 'object') {
    throw new Error('sealed payload has no entry');
  }
  const entry = { ...(parsed.entry as Entry) };
  if (label.length > 0) entry.label = label;
  return vault.adoptEntry(entry, 'sealed');
}

/**
 * Export one entry as a v2 envelope with a single pbkdf2 slot. The default shape
 * is a `VaultBackup` (`opl-vault-entry-v1`) whose `encryptedVault` is base64 of
 * `{ entry }`. With `{ as: 'native' }`, `wif` and `account` kinds are exported as
 * `WifBackup` / `BapAccountBackup` for older readers; every other kind throws.
 */
export async function exportEncrypted(
  vault: Vault,
  id: string,
  passphrase: string,
  opts: { as?: 'native' } = {},
): Promise<string> {
  if (opts.as === 'native') {
    const entry = vault.readForExport(id, 'encrypted-native');
    if (entry.kind === 'wif') {
      return sealBackup({ wif: entry.value, label: entry.label, createdAt: entry.createdAt }, [
        { type: 'pbkdf2', id: `export-${randomSuffix()}`, passphrase },
      ]);
    }
    if (entry.kind === 'account') {
      const parsed = JSON.parse(entry.value) as { wif: string; id: string };
      return sealBackup(
        { wif: parsed.wif, id: parsed.id, label: entry.label, createdAt: entry.createdAt },
        [{ type: 'pbkdf2', id: `export-${randomSuffix()}`, passphrase }],
      );
    }
    throw new Error(`entry kind '${entry.kind}' has no native export form`);
  }
  const entry = vault.readForExport(id, 'encrypted');
  const payload: VaultBackup = {
    encryptedVault: base64Utf8(JSON.stringify({ entry })),
    scheme: VAULT_ENTRY_SCHEME,
  };
  return sealBackup(payload, [{ type: 'pbkdf2', id: `export-${randomSuffix()}`, passphrase }]);
}

/**
 * Seal one entry for `recipientPublicKeyHex` (65-byte uncompressed P-256 hex) via
 * `eciesEncrypt` over UTF-8 JSON `{ entry }`. Logs a line recording the recipient.
 */
export async function exportSealed(
  vault: Vault,
  id: string,
  recipientPublicKeyHex: string,
): Promise<Uint8Array> {
  const entry = vault.readForExport(id, recipientPublicKeyHex);
  return eciesEncrypt(recipientPublicKeyHex, new TextEncoder().encode(JSON.stringify({ entry })));
}

/** Seal the whole document as a v2 envelope with a single pbkdf2 slot. */
export async function exportDocument(vault: Vault, passphrase: string): Promise<string> {
  vault.logExport('document');
  const payload: VaultBackup = {
    encryptedVault: base64Utf8(JSON.stringify(vault.toDocument())),
    scheme: VAULT_SCHEME,
  };
  return sealBackup(payload, [{ type: 'pbkdf2', id: `export-${randomSuffix()}`, passphrase }]);
}
