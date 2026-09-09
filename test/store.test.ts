process.env.VAULT_ARGON2_FAST = '1';

import { afterEach, describe, expect, test } from 'bun:test';
import { mkdtempSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { isEnvelopeV2, openBackup } from 'bitcoin-backup';
import { DeviceKeyProvider } from '../src/providers/device-p256.js';
import { PassphraseProvider } from '../src/providers/passphrase.js';
import type { SealingProvider } from '../src/providers/provider.js';
import {
  addVaultSlot,
  createVault,
  defaultVaultPath,
  inspectVault,
  openVault,
  removeVaultSlot,
  rewrapVault,
  saveVault,
} from '../src/store.js';

const PASS = 'correct horse battery staple';
const OTHER_PASS = 'another fine passphrase here';

function tmpVault(): string {
  return join(mkdtempSync(join(tmpdir(), 'vault-store-')), 'vault.bep');
}

function fakeEnclave(device: DeviceKeyProvider): SealingProvider {
  return {
    type: 'enclave',
    isSupported: () => true,
    publicKey: () => device.publicKey(),
    wrap: (key: Uint8Array) => device.wrap(key),
    unwrap: (wrapped: Uint8Array) => device.unwrap(wrapped),
  };
}

const savedVaultPath = process.env.VAULT_PATH;
afterEach(() => {
  if (savedVaultPath === undefined) delete process.env.VAULT_PATH;
  else process.env.VAULT_PATH = savedVaultPath;
});

describe('store with a passphrase slot', () => {
  test('create -> save -> open round trip', async () => {
    const path = tmpVault();
    const provider = new PassphraseProvider(PASS);
    const vault = await createVault(path, [provider]);
    vault.generateEntropy('root');
    await saveVault(path, vault, provider);

    const opened = await openVault(path, new PassphraseProvider(PASS));
    expect(opened.list()).toHaveLength(1);
    expect(opened.list()[0].label).toBe('root');
    await expect(openVault(path, new PassphraseProvider(OTHER_PASS))).rejects.toThrow();
  });

  test('on-disk payload is a v2 envelope over { encryptedVault, scheme }', async () => {
    const path = tmpVault();
    const vault = await createVault(path, [new PassphraseProvider(PASS)]);
    vault.generateEntropy('root');
    await saveVault(path, vault, new PassphraseProvider(PASS));

    const { readFile } = await import('node:fs/promises');
    const raw = await readFile(path, 'utf8');
    expect(isEnvelopeV2(raw)).toBe(true);
    const payload = (await openBackup(raw, { passphrase: PASS })) as Record<string, unknown>;
    expect(payload.scheme).toBe('opl-vault-v1');
    const doc = JSON.parse(
      Buffer.from(payload.encryptedVault as string, 'base64').toString('utf8'),
    ) as { entries: Array<{ label: string }> };
    expect(doc.entries.map((e) => e.label)).toEqual(['root']);
  });

  test('passphrase plus device slots both open, then remove one', async () => {
    const path = tmpVault();
    const passphrase = new PassphraseProvider(PASS);
    const device = await DeviceKeyProvider.generate();
    const vault = await createVault(path, [passphrase, device]);
    vault.generateEntropy('root');
    await saveVault(path, vault, passphrase);

    const byPass = await openVault(path, new PassphraseProvider(PASS));
    expect(byPass.list()).toHaveLength(1);
    const byDevice = await openVault(path, device);
    expect(byDevice.list()).toHaveLength(1);

    const slots = (await inspectVault(path)).slots;
    expect(slots).toHaveLength(2);
    const deviceSlot = slots.find((s) => s.type === 'device-p256');
    expect(deviceSlot?.publicKey).toBe((await device.publicKey()).toLowerCase());

    await removeVaultSlot(path, new PassphraseProvider(PASS), deviceSlot?.id as string);
    const after = await openVault(path, new PassphraseProvider(PASS));
    expect(after.list()).toHaveLength(1);
    await expect(openVault(path, device)).rejects.toThrow();

    const remaining = (await inspectVault(path)).slots;
    await expect(
      removeVaultSlot(path, new PassphraseProvider(PASS), remaining[0].id),
    ).rejects.toThrow(/last slot/);
  });

  test('device-p256 slot alone round trips', async () => {
    const path = tmpVault();
    const device = await DeviceKeyProvider.generate();
    const vault = await createVault(path, [device]);
    vault.generateEntropy('root');
    await saveVault(path, vault, device);
    const opened = await openVault(path, device);
    expect(opened.list()).toHaveLength(1);
    await expect(openVault(path, await DeviceKeyProvider.generate())).rejects.toThrow();
  });

  test('addVaultSlot adds a device slot to a passphrase vault', async () => {
    const path = tmpVault();
    await createVault(path, [new PassphraseProvider(PASS)]);
    const device = await DeviceKeyProvider.generate();
    const id = await addVaultSlot(path, new PassphraseProvider(PASS), device);
    expect(id.startsWith('device-p256-')).toBe(true);
    const opened = await openVault(path, device);
    expect(opened.list()).toHaveLength(0);
    expect((await inspectVault(path)).slots).toHaveLength(2);
  });

  test('rewrapVault keeps the vault openable with the same provider', async () => {
    const path = tmpVault();
    const vault = await createVault(path, [new PassphraseProvider(PASS)]);
    vault.generateEntropy('root');
    await saveVault(path, vault, new PassphraseProvider(PASS));
    const before = (await inspectVault(path)).slots.map((s) => s.id);
    await rewrapVault(path, new PassphraseProvider(PASS));
    const after = (await inspectVault(path)).slots.map((s) => s.id);
    expect(after).toEqual(before);
    const opened = await openVault(path, new PassphraseProvider(PASS));
    expect(opened.list()).toHaveLength(1);
  });
});

describe('inspectVault', () => {
  test('returns slot metadata without unlocking', async () => {
    const path = tmpVault();
    await createVault(path, [new PassphraseProvider(PASS)]);
    const inspected = await inspectVault(path);
    expect(inspected.version).toBe(2);
    expect(inspected.slots).toHaveLength(1);
    expect(inspected.slots[0].type).toBe('argon2id');
    expect(inspected.slots[0].id.startsWith('passphrase-')).toBe(true);
    expect(inspected.slots[0].publicKey).toBeUndefined();
  });
});

describe('defaultVaultPath', () => {
  test('defaults under home, honors VAULT_PATH verbatim, empty throws', () => {
    delete process.env.VAULT_PATH;
    expect(defaultVaultPath()).toBe(join(homedir(), '.bsv', 'vault.bep'));
    process.env.VAULT_PATH = '/tmp/custom vault.bep';
    expect(defaultVaultPath()).toBe('/tmp/custom vault.bep');
    process.env.VAULT_PATH = '';
    expect(() => defaultVaultPath()).toThrow(/VAULT_PATH.*empty/);
  });
});

describe('single-enclave refusal', () => {
  test('lone enclave slot without passphrase is refused unless allowed', async () => {
    const device = await DeviceKeyProvider.generate();
    await expect(createVault(tmpVault(), [fakeEnclave(device)])).rejects.toThrow(/enclave/);
    const path = tmpVault();
    const allowed = await createVault(path, [fakeEnclave(device)], {
      allowSingleHardwareSlot: true,
    });
    allowed.generateEntropy('root');
    await saveVault(path, allowed, fakeEnclave(device));
    const opened = await openVault(path, fakeEnclave(device));
    expect(opened.list()).toHaveLength(1);
  });
});
