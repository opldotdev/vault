import { describe, expect, test } from 'bun:test';
import { HD, Mnemonic, PrivateKey } from '@bsv/sdk';
import { BRC157_PHRASE, hexToBytes, mnemonicToEntropy } from '../src/derive.js';
import { validateDocument } from '../src/document.js';
import { SessionExpired } from '../src/signer.js';
import { createVaultDocument, Vault } from '../src/vault.js';

function setup(settings?: { revealEnabled?: boolean; unlockTtlSeconds?: number }) {
  let t = 1_700_000_000_000;
  const now = () => t;
  const advance = (ms: number) => {
    t += ms;
  };
  const vault = new Vault(createVaultDocument(settings), { now });
  return { vault, now, advance };
}

function randomWif(): string {
  return PrivateKey.fromRandom().toWif();
}

function legacyXprv(): { xprv: string; mnemonic: string } {
  const entropy = hexToBytes(mnemonicToEntropy(BRC157_PHRASE));
  const master = HD.fromSeed(Mnemonic.fromEntropy(entropy).toSeed());
  return { xprv: master.toString(), mnemonic: BRC157_PHRASE };
}

describe('vault', () => {
  test('createVaultDocument defaults', () => {
    const doc = createVaultDocument();
    expect(doc.version).toBe(1);
    expect(doc.settings.revealEnabled).toBe(true);
    expect(doc.settings.unlockTtlSeconds).toBe(300);
    expect(validateDocument(doc)).toBeTruthy();
  });

  test('list/get strip values and filter', () => {
    const { vault } = setup();
    const entropy = vault.generateEntropy('root');
    vault.generateSymmetric('sym');
    expect(vault.list()).toHaveLength(2);
    for (const item of vault.list()) {
      expect('value' in item).toBe(false);
    }
    expect(vault.list({ kind: 'entropy' })).toHaveLength(1);
    expect(vault.list({ kind: 'wif' })).toHaveLength(0);
    expect(vault.get(entropy.id).id).toBe(entropy.id);
    expect(() => vault.get('missing')).toThrow();
  });

  test('unlock and lock append log lines', () => {
    const { vault } = setup();
    vault.unlock('testing');
    vault.lock();
    const ops = vault.toDocument().log.map((l) => l.op);
    expect(ops).toEqual(['unlock', 'lock']);
    expect(vault.toDocument().log[0].reason).toBe('testing');
  });

  test('importPlain handles every bitcoin-backup payload', () => {
    const { vault } = setup();
    const wif = randomWif();

    const wifEntries = vault.importPlain({ wif }, 'w');
    expect(wifEntries).toHaveLength(1);
    expect(wifEntries[0].kind).toBe('wif');

    const account = vault.importPlain({ wif, id: 'alice' }, 'a');
    expect(account[0].kind).toBe('account');
    expect(account[0].value).toBe(JSON.stringify({ wif, id: 'alice' }));

    const rootHex = PrivateKey.fromRandom().toHex().padStart(64, '0');
    const type42 = vault.importPlain({ ids: 'id-1', rootPk: rootHex }, 't');
    expect(type42[0].kind).toBe('private');
    expect(type42[0].metadata.ids).toBe('id-1');

    const { xprv, mnemonic } = legacyXprv();
    const legacy = vault.importPlain({ ids: 'id-2', xprv, mnemonic }, 'legacy');
    expect(legacy.map((e) => e.kind).sort()).toEqual(['hd-private', 'mnemonic']);

    const onesat = vault.importPlain(
      { ordPk: randomWif(), payPk: randomWif(), identityPk: randomWif() },
      'onesat',
    );
    expect(onesat).toHaveLength(3);
    expect(onesat[0].roles).toEqual({ ordinals: true });
    expect(onesat[1].roles).toEqual({ funding: true });
    expect(onesat[2].roles).toEqual({ identity: true });

    const sigma = vault.importPlain(
      {
        format: 'sigma-seed',
        version: 1,
        mnemonic: BRC157_PHRASE,
        profiles: [{ index: 0, bapId: 'test-bap-id' }],
        nextProfileIndex: 1,
        createdAt: 123,
      },
      'sigma',
    );
    expect(sigma[0].kind).toBe('mnemonic');
    expect(sigma[0].derivation?.scheme).toBe('brc157');

    expect(() => vault.importPlain({ nope: true }, 'x')).toThrow();
    expect(() => vault.importPlain('wif-string', 'x')).toThrow();
  });

  test('generate methods produce well-formed entries', () => {
    const { vault } = setup();
    const entropy = vault.generateEntropy('e');
    expect(entropy.kind).toBe('entropy');
    expect(entropy.value).toHaveLength(64);
    const key = vault.generateKey('k');
    expect(key.kind).toBe('private');
    expect(key.publicKey).toHaveLength(66);
    const sym = vault.generateSymmetric('s');
    expect(sym.kind).toBe('symmetric');
    expect(sym.value).toHaveLength(64);
  });

  test('derive brc157 root and profile', () => {
    const { vault } = setup();
    const entropy = vault.generateEntropy('root');
    entropy.value = mnemonicToEntropy(BRC157_PHRASE);
    const root = vault.derive(entropy.id, { scheme: 'brc157' }, 'root-key');
    expect(root.kind).toBe('private');
    expect(root.publicKey).toBe(vault.identityKey(entropy.id));
    const profile = vault.derive(entropy.id, { scheme: 'brc157', index: 1 }, 'p1');
    expect(profile.derivation?.index).toBe(1);
    expect(profile.value).not.toBe(root.value);
    expect(() => vault.derive(entropy.id, { scheme: 'type42' }, 'x')).toThrow(
      'unsupported in this version',
    );
  });

  test('derive bip32 from an hd-private entry', () => {
    const { vault } = setup();
    const { xprv, mnemonic } = legacyXprv();
    const [mnemonicEntry, hdEntry] = vault.importPlain({ ids: 'i', xprv, mnemonic }, 'legacy');
    void mnemonicEntry;
    const child = vault.derive(hdEntry.id, { scheme: 'bip32', path: 'm/0/1' }, 'child');
    expect(child.kind).toBe('hd-private');
    expect(child.value).not.toBe(xprv);
    expect(child.publicKey).toHaveLength(66);
  });

  test('derive brc42 from a private entry', () => {
    const { vault } = setup();
    const key = vault.generateKey('root');
    const child = vault.derive(
      key.id,
      { scheme: 'brc42', brc42: { protocolID: [2, 'vault test'], keyID: 'k1' } },
      'derived',
    );
    expect(child.kind).toBe('private');
    expect(child.value).not.toBe(key.value);
  });

  test('publicKey and identityKey', () => {
    const { vault } = setup();
    const entropy = vault.generateEntropy('root');
    entropy.value = mnemonicToEntropy(BRC157_PHRASE);
    expect(vault.identityKey(entropy.id)).toHaveLength(66);
    expect(vault.publicKey(entropy.id)).toBe(vault.identityKey(entropy.id));
    const key = vault.generateKey('k');
    expect(vault.identityKey(key.id)).toBe(key.publicKey);
    const wif = vault.importPlain({ wif: randomWif() }, 'w')[0];
    expect(vault.publicKey(wif.id)).toHaveLength(66);
    expect(() => vault.publicKey(vault.generateSymmetric('s').id)).toThrow();
  });

  test('profile creates a brc157 entry', () => {
    const { vault } = setup();
    const entropy = vault.generateEntropy('root');
    const p0 = vault.profile(entropy.id, 0, 'p0');
    const p1 = vault.profile(entropy.id, 1, 'p1');
    expect(p0.value).not.toBe(p1.value);
    expect(p0.derivation).toMatchObject({ scheme: 'brc157', index: 0, path: "m/0'/0'" });
    expect(p0.derivation?.parentIdentityKey).toBe(vault.identityKey(entropy.id));
  });

  test('signer requires a session and refuses roots', async () => {
    const { vault } = setup();
    const key = vault.generateKey('k');
    expect(() => vault.signer(key.id)).toThrow(SessionExpired);
    vault.unlock('test', 60);
    const signer = vault.signer(key.id);
    expect(signer.publicKey()).toBe(key.publicKey);
    const entropy = vault.generateEntropy('root');
    expect(() => vault.signer(entropy.id)).toThrow('roots do not sign');
    const data = new TextEncoder().encode('sign me');
    const sig = await signer.sign(data);
    expect(sig.length).toBeGreaterThan(0);
  });

  test('session expiry blocks signer creation', () => {
    const { vault, advance } = setup();
    const key = vault.generateKey('k');
    vault.unlock('test', 60);
    vault.signer(key.id);
    advance(61_000);
    expect(() => vault.signer(key.id)).toThrow(SessionExpired);
  });

  test('split and recover round trip', () => {
    const { vault } = setup();
    const entropy = vault.generateEntropy('root');
    const shares = vault.split(entropy.id, 2, 3);
    expect(shares).toHaveLength(3);
    expect(shares.every((s) => s.kind === 'share')).toBe(true);
    expect(vault.toDocument().entries.find((e) => e.id === entropy.id)?.shares?.threshold).toBe(2);
    const recovered = vault.recover([shares[0].id, shares[2].id], 'recovered');
    expect(recovered.kind).toBe('entropy');
    expect(recovered.value).toBe(entropy.value);
  });

  test('reveal gate and logging', () => {
    const locked = setup({ revealEnabled: false });
    const keyA = locked.vault.generateKey('k');
    expect(() => locked.vault.reveal(keyA.id, 'reason')).toThrow('reveal is disabled');
    const failedLog = locked.vault.toDocument().log.at(-1);
    expect(failedLog?.op).toBe('reveal');
    expect(failedLog?.ok).toBe(false);

    const { vault } = setup();
    const key = vault.generateKey('k');
    expect(vault.reveal(key.id, 'migration')).toBe(key.value);
    const line = vault.toDocument().log.at(-1);
    expect(line?.op).toBe('reveal');
    expect(line?.reason).toBe('migration');
    expect(line?.ok).toBe(true);
  });

  test('log never contains secret material', () => {
    const { vault } = setup();
    vault.unlock('audit');
    const entropy = vault.generateEntropy('root');
    const key = vault.generateKey('k');
    vault.derive(entropy.id, { scheme: 'brc157' }, 'd');
    vault.profile(entropy.id, 0, 'p');
    const shares = vault.split(entropy.id, 2, 3);
    vault.recover([shares[0].id, shares[1].id], 'r');
    const signer = vault.signer(key.id);
    void signer;
    vault.reveal(key.id, 'audit');
    vault.lock();
    const dumped = JSON.stringify(vault.toDocument().log);
    for (const secret of [entropy.value, key.value]) {
      expect(dumped).not.toContain(secret);
    }
  });

  test('toDocument round-trips through validateDocument', () => {
    const { vault } = setup();
    vault.unlock('x');
    vault.generateEntropy('e');
    expect(validateDocument(vault.toDocument()).entries).toHaveLength(1);
  });
});
