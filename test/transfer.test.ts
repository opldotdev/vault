import { describe, expect, test } from 'bun:test';
import { PrivateKey } from '@bsv/sdk';
import { decryptBackup, eciesDecrypt, encryptBackup, openBackup, sealBackup } from 'bitcoin-backup';
import { DeviceKeyProvider } from '../src/providers/device-p256.js';
import { PassphraseProvider } from '../src/providers/passphrase.js';
import {
  exportDocument,
  exportEncrypted,
  exportSealed,
  importEncrypted,
  importSealed,
} from '../src/transfer.js';
import { createVaultDocument, Vault } from '../src/vault.js';

const PASS = 'correct horse battery staple';

function setup() {
  return new Vault(createVaultDocument());
}

function randomWif(): string {
  return PrivateKey.fromRandom().toWif();
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

describe('transfer', () => {
  test('v1 WifBackup imports via passphrase', async () => {
    const wif = randomWif();
    const bep = await encryptBackup({ wif }, PASS);
    const vault = setup();
    const entries = await importEncrypted(vault, bep, { passphrase: PASS }, 'v1-wif');
    expect(entries).toHaveLength(1);
    expect(entries[0].kind).toBe('wif');
    expect(entries[0].label).toBe('v1-wif');
    expect(entries[0].value).toBe(wif);
  });

  test('v2 envelope imports via passphrase and via provider', async () => {
    const wif = randomWif();
    const device = await DeviceKeyProvider.generate();
    const bep = await sealBackup({ wif }, [
      { type: 'pbkdf2', id: 'passphrase-1', passphrase: PASS },
      { type: 'device-p256', id: 'device-1', publicKey: await device.publicKey() },
    ]);

    const byPass = setup();
    const a = await importEncrypted(byPass, bep, { passphrase: PASS }, 'v2-wif');
    expect(a).toHaveLength(1);
    expect(a[0].value).toBe(wif);

    const byProvider = setup();
    const b = await importEncrypted(
      byProvider,
      bep,
      { provider: new PassphraseProvider(PASS) },
      'v2-wif',
    );
    expect(b).toHaveLength(1);
    expect(b[0].value).toBe(wif);

    const byDevice = setup();
    const c = await importEncrypted(byDevice, bep, { provider: device }, 'v2-wif');
    expect(c).toHaveLength(1);
    expect(c[0].value).toBe(wif);
  });

  test('foreign opl-vault-v1 document import preserves fields with new ids', async () => {
    const source = setup();
    const wif = randomWif();
    source.generateKey('key-a');
    const root = source.generateEntropy('root');
    const prof = source.profile(root.id, 2, 'prof-2');
    source.importPlain({ ordPk: randomWif(), payPk: randomWif(), identityPk: randomWif() }, 'os');
    const planted = source.adoptEntry({
      id: 'foreign-id',
      kind: 'wif',
      label: 'tagged',
      tags: ['hot', 'cold'],
      createdAt: '2024-01-01T00:00:00.000Z',
      updatedAt: '2024-01-01T00:00:00.000Z',
      value: wif,
      roles: { encryption: true },
      metadata: { origin: 'foreign' },
    });
    const before = source.toDocument().entries.length;

    const bep = await exportDocument(source, PASS);
    const target = setup();
    const logBefore = target.toDocument().log.length;
    const imported = await importEncrypted(target, bep, { passphrase: PASS }, 'ignored-label');

    expect(imported).toHaveLength(before);
    const byLabel = new Map(imported.map((e) => [e.label, e]));
    expect([...byLabel.keys()].sort()).toEqual(
      source
        .toDocument()
        .entries.map((e) => e.label)
        .sort(),
    );
    for (const entry of imported) {
      expect(entry.id).not.toBe('foreign-id');
    }
    const tagged = byLabel.get('tagged');
    expect(tagged?.tags).toEqual(['hot', 'cold']);
    expect(tagged?.roles).toEqual({ encryption: true });
    expect(tagged?.metadata).toEqual({ origin: 'foreign' });
    expect(tagged?.value).toBe(wif);
    const profCopy = byLabel.get('prof-2');
    expect(profCopy?.derivation).toEqual(prof.derivation);
    const ordinals = imported.find((e) => e.label === 'os ordinals');
    expect(ordinals?.roles).toEqual({ ordinals: true });
    expect(planted.id).not.toBe(tagged?.id);
    const newLogs = target
      .toDocument()
      .log.slice(logBefore)
      .filter((l) => l.op === 'import');
    expect(newLogs).toHaveLength(before);
  });

  test('exportSealed decrypts with eciesDecrypt and reimports via importSealed', async () => {
    const vault = setup();
    const entry = vault.generateKey('sealed-key');
    const secret = entry.value;

    // Independent keypair: decrypt with bitcoin-backup's eciesDecrypt in the test.
    const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
      'deriveBits',
    ]);
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey as CryptoKey));
    const hex = toHex(raw);
    const wrapped = await exportSealed(vault, entry.id, hex);
    const plain = await eciesDecrypt(pair.privateKey as CryptoKey, wrapped);
    const parsed = JSON.parse(new TextDecoder().decode(plain)) as {
      entry: { id: string; value: string; label: string };
    };
    expect(parsed.entry.value).toBe(secret);
    expect(parsed.entry.label).toBe('sealed-key');
    const exportLog = vault.toDocument().log.filter((l) => l.op === 'export');
    expect(exportLog).toHaveLength(1);
    expect(exportLog[0].detail).toBe(hex);

    // DeviceKeyProvider unwrap path.
    const device = await DeviceKeyProvider.generate();
    const forDevice = await exportSealed(vault, entry.id, await device.publicKey());
    const target = setup();
    const reimported = await importSealed(target, forDevice, device, 'sealed-key');
    expect(reimported.value).toBe(secret);
    expect(reimported.label).toBe('sealed-key');
    expect(reimported.id).not.toBe(entry.id);
  });

  test('exportEncrypted default and native forms round trip', async () => {
    const vault = setup();
    const wif = randomWif();
    const [wifEntry] = vault.importPlain({ wif }, 'native-wif');
    const [accountEntry] = vault.importPlain({ wif, id: 'alice' }, 'native-account');

    // Default single-entry envelope.
    const def = await exportEncrypted(vault, wifEntry.id, PASS);
    const defPayload = (await openBackup(def, { passphrase: PASS })) as Record<string, unknown>;
    expect(defPayload.scheme).toBe('opl-vault-entry-v1');
    const target = setup();
    const [restored] = await importEncrypted(target, def, { passphrase: PASS }, 'unused');
    expect(restored.value).toBe(wif);
    expect(restored.label).toBe('native-wif');

    // Native wif.
    const nativeWif = await exportEncrypted(vault, wifEntry.id, PASS, { as: 'native' });
    const wifPayload = (await openBackup(nativeWif, { passphrase: PASS })) as { wif: string };
    expect(wifPayload.wif).toBe(wif);
    expect(await decryptBackup(nativeWif, PASS)).toEqual(wifPayload);

    // Native account.
    const nativeAccount = await exportEncrypted(vault, accountEntry.id, PASS, { as: 'native' });
    const accountPayload = (await openBackup(nativeAccount, { passphrase: PASS })) as {
      wif: string;
      id: string;
    };
    expect(accountPayload.wif).toBe(wif);
    expect(accountPayload.id).toBe('alice');
    const target2 = setup();
    const [restoredAccount] = await importEncrypted(
      target2,
      nativeAccount,
      { passphrase: PASS },
      'unused',
    );
    expect(restoredAccount.kind).toBe('account');
  });

  test('exportDocument reopens with every entry', async () => {
    const vault = setup();
    vault.generateEntropy('root');
    vault.generateSymmetric('sym');
    const bep = await exportDocument(vault, PASS);
    const target = setup();
    const imported = await importEncrypted(target, bep, { passphrase: PASS }, 'unused');
    expect(imported).toHaveLength(2);
    expect(imported.map((e) => e.label).sort()).toEqual(['root', 'sym']);
  });

  test("non-native kinds refuse 'native' export", async () => {
    const vault = setup();
    const entropy = vault.generateEntropy('root');
    const sym = vault.generateSymmetric('sym');
    await expect(exportEncrypted(vault, entropy.id, PASS, { as: 'native' })).rejects.toThrow(
      /no native export form/,
    );
    await expect(exportEncrypted(vault, sym.id, PASS, { as: 'native' })).rejects.toThrow(
      /no native export form/,
    );
  });

  test('exports do not use reveal (work with reveal disabled)', async () => {
    const vault = new Vault(createVaultDocument({ revealEnabled: false }));
    const entry = vault.generateKey('k');
    expect(() => vault.reveal(entry.id, 'nope')).toThrow(/disabled/);
    const bep = await exportEncrypted(vault, entry.id, PASS);
    const target = setup();
    const [restored] = await importEncrypted(target, bep, { passphrase: PASS }, 'unused');
    expect(restored.value).toBe(vault.readForExport(entry.id).value);
    const device = await DeviceKeyProvider.generate();
    const wrapped = await exportSealed(vault, entry.id, await device.publicKey());
    const reimported = await importSealed(target, wrapped, device, 'k');
    expect(reimported.value).toBe(vault.readForExport(entry.id).value);
  });
});
