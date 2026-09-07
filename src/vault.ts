import { HD, PrivateKey } from '@bsv/sdk';
import {
  type DecryptedBackup,
  getBackupType,
  isAccountBackup,
  isLegacyBackup,
  isOneSatBackup,
  isSigmaSeedBackup,
  isType42Backup,
  isWifBackup,
} from 'bitcoin-backup';
import {
  type Brc42Params,
  bip32Derive,
  brc42Derive,
  brc42DerivePublicKey,
  brc157IdentityKey,
  brc157Profile,
  brc157Root,
  bytesToHex,
  mnemonicToEntropy,
  privateKeyToHex,
  publicKeyHex,
  throwIfType42,
} from './derive.js';
import {
  type DerivationDescriptor,
  type Entry,
  type EntryKind,
  isoNow,
  type LogLine,
  randomId,
  type VaultDocument,
  validateDocument,
  validateEntry,
} from './document.js';
import { recoverEntropy, splitEntropy } from './shares.js';
import { createSigner, SessionExpired, type Signer } from './signer.js';

export interface VaultOptions {
  now?: () => number;
}

export interface ListFilter {
  kind?: EntryKind;
  tag?: string;
  role?: 'identity' | 'funding' | 'ordinals' | 'encryption';
}

export type PublicEntry = Omit<Entry, 'value'>;

/** A derivation request: the descriptor to record, plus BRC-42 parameters when the scheme is brc42. */
export type DeriveSpec = DerivationDescriptor & { brc42?: Brc42Params };

export function createVaultDocument(settings?: {
  revealEnabled?: boolean;
  unlockTtlSeconds?: number;
}): VaultDocument {
  return {
    version: 1,
    id: randomId(),
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    settings: {
      revealEnabled: settings?.revealEnabled ?? true,
      unlockTtlSeconds: settings?.unlockTtlSeconds ?? 300,
    },
    entries: [],
    log: [],
  };
}

function strip(entry: Entry): PublicEntry {
  const { value: _value, ...rest } = entry;
  return rest;
}

function randomHex32(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytesToHex(Array.from(bytes));
}

function pubkeyFromWif(wif: string): string {
  return publicKeyHex(PrivateKey.fromWif(wif));
}

function pubkeyFromHex(hex: string): string {
  return publicKeyHex(PrivateKey.fromHex(hex));
}

function pubkeyFromXprv(xprv: string): string {
  return publicKeyHex(HD.fromString(xprv).privKey);
}

function pubkeyFromXpub(xpub: string): string {
  return HD.fromString(xpub).pubKey.encode(true, 'hex') as string;
}

export class Vault {
  private doc: VaultDocument;
  private readonly now: () => number;
  private session: { reason: string; expiresAt: number } | null = null;

  constructor(doc: VaultDocument, opts: VaultOptions = {}) {
    this.doc = validateDocument(structuredClone(doc));
    this.now = opts.now ?? Date.now;
  }

  private appendLog(op: string, fields: Partial<LogLine> = {}): void {
    this.doc.log.push({
      at: isoNow(this.now),
      op,
      ok: true,
      ...fields,
    });
    this.doc.updatedAt = isoNow(this.now);
  }

  private find(id: string): Entry {
    const entry = this.doc.entries.find((e) => e.id === id);
    if (!entry) throw new Error(`unknown entry: ${id}`);
    return entry;
  }

  private makeEntry(
    kind: EntryKind,
    label: string,
    value: string,
    opts: Partial<Entry> = {},
  ): Entry {
    const at = isoNow(this.now);
    const { tags = [], metadata = {}, ...rest } = opts;
    const entry: Entry = {
      id: randomId(),
      kind,
      label,
      tags,
      createdAt: at,
      updatedAt: at,
      value,
      metadata,
      ...rest,
    };
    this.doc.entries.push(entry);
    return entry;
  }

  private entropyOf(entry: Entry): string {
    if (entry.kind === 'entropy') return entry.value;
    if (entry.kind === 'mnemonic') return mnemonicToEntropy(entry.value);
    throw new Error(`entry ${entry.id} is not an entropy source`);
  }

  private signingKeyOf(entry: Entry): PrivateKey {
    switch (entry.kind) {
      case 'private':
        return PrivateKey.fromHex(entry.value);
      case 'wif':
        return PrivateKey.fromWif(entry.value);
      case 'account': {
        const parsed = JSON.parse(entry.value) as { wif: string };
        return PrivateKey.fromWif(parsed.wif);
      }
      case 'hd-private':
        return HD.fromString(entry.value).privKey;
      default:
        throw new Error(`entry ${entry.id} cannot sign`);
    }
  }

  private brc42Params(spec: DeriveSpec): {
    protocolID: Brc42Params['protocolID'];
    keyID: string;
    counterparty: string;
  } {
    if (!spec.brc42) throw new Error('brc42 derivation requires brc42 parameters');
    return { ...spec.brc42, counterparty: spec.brc42.counterparty ?? 'self' };
  }

  list(filter: ListFilter = {}): PublicEntry[] {
    return this.doc.entries
      .filter(
        (e) =>
          (filter.kind === undefined || e.kind === filter.kind) &&
          (filter.tag === undefined || e.tags.includes(filter.tag)) &&
          (filter.role === undefined || e.roles?.[filter.role] === true),
      )
      .map(strip);
  }

  get(id: string): PublicEntry {
    return strip(this.find(id));
  }

  unlock(reason: string, ttlSeconds?: number): void {
    const ttl = ttlSeconds ?? this.doc.settings.unlockTtlSeconds;
    this.session = { reason, expiresAt: this.now() + ttl * 1000 };
    this.appendLog('unlock', { reason, ok: true });
  }

  lock(): void {
    this.session = null;
    this.appendLog('lock', { ok: true });
  }

  importPlain(payload: unknown, label: string): Entry[] {
    if (typeof payload !== 'object' || payload === null)
      throw new Error('unsupported backup payload');
    const backup = payload as unknown as DecryptedBackup;
    const base = label;
    const created: Entry[] = [];
    const detail = (() => {
      try {
        return getBackupType(backup);
      } catch {
        return 'Unknown';
      }
    })();

    if (isSigmaSeedBackup(backup)) {
      created.push(
        this.makeEntry('mnemonic', base, backup.mnemonic, { derivation: { scheme: 'brc157' } }),
      );
    } else if (isOneSatBackup(backup)) {
      created.push(
        this.makeEntry('wif', `${base} ordinals`, backup.ordPk, {
          publicKey: pubkeyFromWif(backup.ordPk),
          roles: { ordinals: true },
        }),
        this.makeEntry('wif', `${base} funding`, backup.payPk, {
          publicKey: pubkeyFromWif(backup.payPk),
          roles: { funding: true },
        }),
        this.makeEntry('wif', `${base} identity`, backup.identityPk, {
          publicKey: pubkeyFromWif(backup.identityPk),
          roles: { identity: true },
        }),
      );
    } else if (isLegacyBackup(backup)) {
      created.push(
        this.makeEntry('mnemonic', base, backup.mnemonic, { metadata: { ids: backup.ids } }),
        this.makeEntry('hd-private', `${base} hd-private`, backup.xprv, {
          publicKey: pubkeyFromXprv(backup.xprv),
          metadata: { ids: backup.ids },
        }),
      );
    } else if (isType42Backup(backup)) {
      let publicKey: string | undefined;
      try {
        publicKey = pubkeyFromWif(backup.rootPk);
      } catch {
        try {
          publicKey = pubkeyFromHex(backup.rootPk);
        } catch {
          publicKey = undefined;
        }
      }
      created.push(
        this.makeEntry('private', base, backup.rootPk, {
          publicKey,
          metadata: { ids: backup.ids },
        }),
      );
    } else if (isAccountBackup(backup)) {
      created.push(
        this.makeEntry('account', base, JSON.stringify({ wif: backup.wif, id: backup.id }), {
          publicKey: pubkeyFromWif(backup.wif),
        }),
      );
    } else if (isWifBackup(backup)) {
      created.push(
        this.makeEntry('wif', base, backup.wif, { publicKey: pubkeyFromWif(backup.wif) }),
      );
    } else {
      throw new Error('unsupported backup payload');
    }

    for (const entry of created) {
      this.appendLog('import', { entryId: entry.id, detail, ok: true });
    }
    return created;
  }

  generateEntropy(label: string): Entry {
    const entry = this.makeEntry('entropy', label, randomHex32());
    this.appendLog('generate', { entryId: entry.id, detail: 'entropy', ok: true });
    return entry;
  }

  generateKey(label: string): Entry {
    const key = PrivateKey.fromRandom();
    const entry = this.makeEntry('private', label, privateKeyToHex(key), {
      publicKey: publicKeyHex(key),
    });
    this.appendLog('generate', { entryId: entry.id, detail: 'private', ok: true });
    return entry;
  }

  generateSymmetric(label: string): Entry {
    const entry = this.makeEntry('symmetric', label, randomHex32());
    this.appendLog('generate', { entryId: entry.id, detail: 'symmetric', ok: true });
    return entry;
  }

  derive(id: string, spec: DeriveSpec, label: string): Entry {
    throwIfType42(spec.scheme);
    const source = this.find(id);
    let entry: Entry;
    if (spec.scheme === 'brc157') {
      const entropyHex = this.entropyOf(source);
      const key =
        spec.index === undefined ? brc157Root(entropyHex) : brc157Profile(entropyHex, spec.index);
      entry = this.makeEntry('private', label, privateKeyToHex(key), {
        publicKey: publicKeyHex(key),
        derivation: {
          scheme: 'brc157',
          path: `m/0'/${spec.index ?? 0}'`,
          parentIdentityKey: brc157IdentityKey(entropyHex),
          ...(spec.index === undefined ? {} : { index: spec.index }),
        },
      });
    } else if (spec.scheme === 'bip32' || spec.scheme === 'legacy-bip32-unhardened') {
      if (source.kind !== 'hd-private' && source.kind !== 'hd-public') {
        throw new Error(`entry ${id} cannot bip32-derive`);
      }
      if (!spec.path) throw new Error('bip32 derivation requires a path');
      const child = bip32Derive(source.value, spec.path);
      entry = this.makeEntry(source.kind, label, child, {
        publicKey: source.kind === 'hd-private' ? pubkeyFromXprv(child) : pubkeyFromXpub(child),
        derivation: { scheme: spec.scheme, path: spec.path },
      });
    } else if (spec.scheme === 'brc42') {
      const key = this.signingKeyOf(source);
      const { protocolID, keyID, counterparty } = this.brc42Params(spec);
      const child = brc42Derive(key.toWif(), protocolID, keyID, counterparty);
      entry = this.makeEntry('private', label, privateKeyToHex(child), {
        publicKey: publicKeyHex(child),
        derivation: {
          scheme: 'brc42',
          path: `${protocolID[0]}:${protocolID[1]}/${keyID}/${counterparty}`,
          parentIdentityKey: publicKeyHex(key),
        },
      });
    } else {
      throw new Error(`unknown derivation scheme: ${spec.scheme as string}`);
    }
    this.appendLog('derive', { entryId: entry.id, detail: spec.scheme, ok: true });
    return entry;
  }

  publicKey(id: string, spec?: DeriveSpec): string {
    const entry = this.find(id);
    if (spec !== undefined) {
      throwIfType42(spec.scheme);
      if (spec.scheme !== 'brc42') throw new Error(`cannot derive public key with ${spec.scheme}`);
      const { protocolID, keyID, counterparty } = this.brc42Params(spec);
      if (entry.kind === 'entropy' || entry.kind === 'mnemonic') {
        const rootWif = brc157Root(this.entropyOf(entry)).toWif();
        return brc42DerivePublicKey(rootWif, protocolID, keyID, counterparty);
      }
      const rootWif = this.signingKeyOf(entry).toWif();
      return brc42DerivePublicKey(rootWif, protocolID, keyID, counterparty);
    }
    switch (entry.kind) {
      case 'entropy':
        return brc157IdentityKey(entry.value);
      case 'mnemonic':
        return brc157IdentityKey(mnemonicToEntropy(entry.value));
      case 'private':
        return pubkeyFromHex(entry.value);
      case 'wif':
        return pubkeyFromWif(entry.value);
      case 'account':
        return pubkeyFromWif((JSON.parse(entry.value) as { wif: string }).wif);
      case 'hd-private':
        return pubkeyFromXprv(entry.value);
      case 'hd-public':
        return entry.publicKey ?? pubkeyFromXpub(entry.value);
      default:
        throw new Error(`entry ${id} has no public key`);
    }
  }

  identityKey(id: string): string {
    const entry = this.find(id);
    if (entry.kind === 'entropy') return brc157IdentityKey(entry.value);
    if (entry.kind === 'mnemonic') return brc157IdentityKey(mnemonicToEntropy(entry.value));
    return this.publicKey(id);
  }

  profile(id: string, index: number, label: string): Entry {
    const source = this.find(id);
    if (source.kind !== 'entropy' && source.kind !== 'mnemonic') {
      throw new Error(`entry ${id} is not brc157-capable`);
    }
    const entropyHex = this.entropyOf(source);
    const key = brc157Profile(entropyHex, index);
    const entry = this.makeEntry('private', label, privateKeyToHex(key), {
      publicKey: publicKeyHex(key),
      derivation: {
        scheme: 'brc157',
        path: `m/0'/${index}'`,
        parentIdentityKey: brc157IdentityKey(entropyHex),
        index,
      },
    });
    this.appendLog('profile', { entryId: entry.id, ok: true });
    return entry;
  }

  signer(id: string, spec?: DeriveSpec): Signer {
    if (!this.session || this.now() > this.session.expiresAt) throw new SessionExpired();
    const entry = this.find(id);
    if (entry.kind === 'entropy' || entry.kind === 'mnemonic') {
      throw new Error('roots do not sign');
    }
    if (entry.derivation?.scheme === 'brc157' && spec === undefined) {
      throw new Error('profile roots sign only through brc42 derivation');
    }
    let key = this.signingKeyOf(entry);
    if (spec !== undefined) {
      throwIfType42(spec.scheme);
      if (spec.scheme !== 'brc42') throw new Error(`cannot sign with ${spec.scheme}`);
      const { protocolID, keyID, counterparty } = this.brc42Params(spec);
      key = brc42Derive(key.toWif(), protocolID, keyID, counterparty);
    }
    const handle = createSigner(key, { expiresAt: this.session.expiresAt }, this.now);
    this.appendLog('signer', { entryId: id, ok: true });
    return handle;
  }

  split(id: string, threshold: number, total: number): Entry[] {
    const source = this.find(id);
    if (source.kind !== 'entropy') throw new Error(`entry ${id} cannot be split`);
    const values = splitEntropy(source.value, threshold, total);
    const shares = values.map((value, i) =>
      this.makeEntry('share', `${source.label} share ${i + 1}`, value, {
        metadata: { sourceId: source.id },
      }),
    );
    source.shares = { threshold, total, shareIds: shares.map((s) => s.id) };
    source.updatedAt = isoNow(this.now);
    for (const share of shares) {
      this.appendLog('split', { entryId: share.id, ok: true });
    }
    return shares;
  }

  recover(shareIds: string[], label: string): Entry {
    const values = shareIds.map((shareId) => {
      const share = this.find(shareId);
      if (share.kind !== 'share') throw new Error(`entry ${shareId} is not a share`);
      return share.value;
    });
    const entropyHex = recoverEntropy(values);
    const entry = this.makeEntry('entropy', label, entropyHex);
    this.appendLog('recover', { entryId: entry.id, ok: true });
    return entry;
  }

  reveal(id: string, reason: string): string {
    const entry = this.find(id);
    if (!this.doc.settings.revealEnabled) {
      this.appendLog('reveal', { entryId: id, reason, ok: false, detail: 'disabled' });
      throw new Error('reveal is disabled');
    }
    this.appendLog('reveal', { entryId: id, reason, ok: true });
    return entry.value;
  }

  /**
   * Read a full entry for export. This is the only export path allowed to touch
   * secrets: it returns a clone and logs an `export` line (never use `reveal()`
   * for exports).
   */
  readForExport(id: string, detail?: string): Entry {
    const entry = this.find(id);
    this.logExport(detail, id);
    return structuredClone(entry);
  }

  /** Record that secrets left the vault. Every export path calls this. */
  logExport(detail?: string, entryId?: string): void {
    this.appendLog('export', {
      ...(entryId === undefined ? {} : { entryId }),
      ...(detail === undefined ? {} : { detail }),
      ok: true,
    });
  }

  /**
   * Adopt a foreign entry with a fresh id, keeping label, tags, derivation,
   * roles, and metadata. Logs one `import` line.
   */
  adoptEntry(entry: Entry, detail?: string): Entry {
    const checked = validateEntry({
      ...entry,
      tags: entry.tags ?? [],
      metadata: entry.metadata ?? {},
    });
    const adopted: Entry = {
      ...structuredClone(checked),
      id: randomId(),
      updatedAt: isoNow(this.now),
    };
    this.doc.entries.push(adopted);
    this.appendLog('import', {
      entryId: adopted.id,
      ...(detail === undefined ? {} : { detail }),
      ok: true,
    });
    return adopted;
  }
  toDocument(): VaultDocument {
    return structuredClone(this.doc);
  }
}
