import { homedir } from 'node:os';
import { join } from 'node:path';
import {
  addSlot,
  type InspectResult,
  inspectEnvelope,
  openBackup,
  removeSlot,
  rewrapBackup,
  type SlotSpec,
  sealBackup,
  type Unlock,
  updateBackupPayload,
  type VaultBackup,
} from 'bitcoin-backup';
import { type VaultDocument, validateDocument } from './document.js';
import { PassphraseProvider } from './providers/passphrase.js';
import type { SealingProvider } from './providers/provider.js';
import { FileStorage } from './storage/file-storage.js';
import { createVaultDocument, Vault } from './vault.js';

/** Scheme marker stored in the backup payload so foreign readers can identify our format. */
export const VAULT_SCHEME = 'opl-vault-v1';

/** Name of the only environment variable consulted by {@link defaultVaultPath}. */
export const VAULT_PATH_ENV = 'VAULT_PATH';

export interface VaultStoreSettings {
  revealEnabled?: boolean;
  unlockTtlSeconds?: number;
  /** Allow creating a vault whose only slot is an enclave slot with no passphrase recovery. */
  allowSingleHardwareSlot?: boolean;
}

export function defaultVaultPath(): string {
  const override = process.env[VAULT_PATH_ENV];
  if (override !== undefined) {
    if (override.length === 0) throw new Error(`${VAULT_PATH_ENV} is set but empty`);
    return override;
  }
  return join(homedir(), '.bsv', 'vault.bep');
}

function randomSuffix(): string {
  const bytes = new Uint8Array(4);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function slotIdFor(provider: SealingProvider): string {
  return `${provider.type}-${randomSuffix()}`;
}

function passphraseOf(provider: SealingProvider): string {
  if (provider instanceof PassphraseProvider) return provider.passphrase;
  if (provider.type === 'passphrase') {
    throw new Error('passphrase provider does not expose its passphrase');
  }
  throw new Error(`provider type '${provider.type}' is not a passphrase provider`);
}

async function providerToSlotSpec(provider: SealingProvider, id: string): Promise<SlotSpec> {
  if (provider.type === 'passphrase') {
    return { type: 'pbkdf2', id, passphrase: passphraseOf(provider) };
  }
  if (provider.type === 'device-p256' || provider.type === 'enclave') {
    if (!provider.publicKey) throw new Error(`provider type '${provider.type}' has no publicKey`);
    return { type: 'device-p256', id, publicKey: await provider.publicKey() };
  }
  throw new Error(`unknown provider type '${(provider as SealingProvider).type}'`);
}

async function providerToUnlock(
  provider: SealingProvider,
  slots: InspectResult['slots'],
): Promise<Unlock> {
  if (provider.type === 'passphrase') {
    return { passphrase: passphraseOf(provider) };
  }
  const deviceSlots = slots.filter((s) => s.type === 'device-p256');
  if (deviceSlots.length === 0) {
    throw new Error(`vault has no device-p256 slot for a '${provider.type}' provider`);
  }
  let match = deviceSlots.length === 1 ? deviceSlots[0] : undefined;
  if (provider.publicKey) {
    const key = (await provider.publicKey()).toLowerCase();
    const found = deviceSlots.find((s) => s.publicKey?.toLowerCase() === key);
    if (found) match = found;
    else if (deviceSlots.length > 1) {
      throw new Error(`no slot matches this '${provider.type}' key`);
    }
  }
  const slot = match ?? deviceSlots[0];
  const slotId = slot.id;
  return { slotId, unwrap: (wrapped: Uint8Array) => provider.unwrap(wrapped) };
}

function encodeDocument(doc: VaultDocument): string {
  return Buffer.from(JSON.stringify(doc), 'utf8').toString('base64');
}

function decodeVaultBackup(payload: unknown): VaultDocument {
  if (typeof payload !== 'object' || payload === null) {
    throw new Error('vault payload is not an object');
  }
  const backup = payload as Partial<VaultBackup>;
  if (backup.scheme !== VAULT_SCHEME) {
    throw new Error(`not an opl vault (scheme '${String(backup.scheme)}')`);
  }
  if (typeof backup.encryptedVault !== 'string') {
    throw new Error('vault payload is missing its encrypted vault document');
  }
  return validateDocument(
    JSON.parse(Buffer.from(backup.encryptedVault, 'base64').toString('utf8')),
  );
}

function vaultBackupPayload(doc: VaultDocument): VaultBackup {
  return { encryptedVault: encodeDocument(doc), scheme: VAULT_SCHEME };
}

async function readEnvelopeText(path: string): Promise<string> {
  const text = await new FileStorage(path).read();
  if (text === null) throw new Error(`vault not found: ${path}`);
  return text;
}

/**
 * Create a new empty vault sealed with one slot per provider and write it to `path`.
 * Refuses a lone enclave slot with no passphrase recovery unless
 * `settings.allowSingleHardwareSlot` is set.
 */
export async function createVault(
  path: string,
  providers: SealingProvider[],
  settings: VaultStoreSettings = {},
): Promise<Vault> {
  if (providers.length === 0) throw new Error('at least one provider is required');
  const hasPassphrase = providers.some((p) => p.type === 'passphrase');
  if (
    !hasPassphrase &&
    providers.length === 1 &&
    providers[0].type === 'enclave' &&
    settings.allowSingleHardwareSlot !== true
  ) {
    throw new Error(
      'refusing to create a vault with only an enclave slot and no passphrase recovery slot',
    );
  }
  const specs: SlotSpec[] = [];
  for (const provider of providers) {
    specs.push(await providerToSlotSpec(provider, slotIdFor(provider)));
  }
  const doc = createVaultDocument({
    revealEnabled: settings.revealEnabled,
    unlockTtlSeconds: settings.unlockTtlSeconds,
  });
  const encrypted = await sealBackup(vaultBackupPayload(doc), specs);
  await new FileStorage(path).write(encrypted);
  return new Vault(doc);
}

/** Open the vault at `path` with `provider`. */
export async function openVault(path: string, provider: SealingProvider): Promise<Vault> {
  const encrypted = await readEnvelopeText(path);
  const inspected = inspectEnvelope(encrypted);
  const unlock = await providerToUnlock(provider, inspected.slots);
  const doc = decodeVaultBackup(await openBackup(encrypted, unlock));
  return new Vault(doc);
}

/**
 * Write `vault`'s current document back to `path`, unlocking with `provider`.
 * Every existing slot is kept: the payload is re-encrypted under the same content key.
 */
export async function saveVault(
  path: string,
  vault: Vault,
  provider: SealingProvider,
): Promise<void> {
  const encrypted = await readEnvelopeText(path);
  const inspected = inspectEnvelope(encrypted);
  const unlock = await providerToUnlock(provider, inspected.slots);
  const next = await updateBackupPayload(encrypted, unlock, vaultBackupPayload(vault.toDocument()));
  await new FileStorage(path).write(next);
}

/** Add a slot for `newProvider`, proving ownership with `unlockProvider`. Returns the slot id. */
export async function addVaultSlot(
  path: string,
  unlockProvider: SealingProvider,
  newProvider: SealingProvider,
): Promise<string> {
  const encrypted = await readEnvelopeText(path);
  const inspected = inspectEnvelope(encrypted);
  const unlock = await providerToUnlock(unlockProvider, inspected.slots);
  const id = slotIdFor(newProvider);
  const next = await addSlot(encrypted, unlock, await providerToSlotSpec(newProvider, id));
  await new FileStorage(path).write(next);
  return id;
}

/** Remove `slotId`, proving ownership with `unlockProvider`. Refuses the last slot. */
export async function removeVaultSlot(
  path: string,
  unlockProvider: SealingProvider,
  slotId: string,
): Promise<void> {
  const encrypted = await readEnvelopeText(path);
  const inspected = inspectEnvelope(encrypted);
  if (inspected.slots.length <= 1) {
    throw new Error(`refusing to remove the last slot ('${slotId}')`);
  }
  const unlock = await providerToUnlock(unlockProvider, inspected.slots);
  const next = await removeSlot(encrypted, unlock, slotId);
  await new FileStorage(path).write(next);
}

/** Rotate the content key, keeping the same slot set (and ids) with fresh wrapping. */
export async function rewrapVault(path: string, unlockProvider: SealingProvider): Promise<void> {
  const encrypted = await readEnvelopeText(path);
  const inspected = inspectEnvelope(encrypted);
  const unlock = await providerToUnlock(unlockProvider, inspected.slots);
  const specs: SlotSpec[] = [];
  for (const slot of inspected.slots) {
    if (slot.type === 'pbkdf2') {
      if (!(unlockProvider instanceof PassphraseProvider)) {
        throw new Error('rewrap needs the passphrase provider to rebuild pbkdf2 slots');
      }
      specs.push({ type: 'pbkdf2', id: slot.id, passphrase: unlockProvider.passphrase });
    } else if (slot.type === 'device-p256') {
      if (!slot.publicKey) throw new Error(`slot '${slot.id}' is missing its public key`);
      specs.push({ type: 'device-p256', id: slot.id, publicKey: slot.publicKey });
    } else {
      throw new Error(`unknown slot type '${slot.type}'`);
    }
  }
  const next = await rewrapBackup(encrypted, unlock, specs);
  await new FileStorage(path).write(next);
}

/**
 * Return slot metadata without unlocking. Entry listing requires unlock;
 * use {@link openVault} for that.
 */
export async function inspectVault(path: string): Promise<InspectResult> {
  return inspectEnvelope(await readEnvelopeText(path));
}
