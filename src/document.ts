export type EntryKind =
  | 'entropy'
  | 'mnemonic'
  | 'hd-private'
  | 'hd-public'
  | 'private'
  | 'wif'
  | 'account'
  | 'share'
  | 'symmetric';

export interface DerivationDescriptor {
  scheme: 'brc157' | 'bip32' | 'type42' | 'brc42' | 'legacy-bip32-unhardened';
  path?: string;
  parentIdentityKey?: string;
  index?: number;
  cohort?: string;
}

export interface Entry {
  id: string;
  kind: EntryKind;
  label: string;
  tags: string[];
  createdAt: string;
  updatedAt: string;
  value: string;
  publicKey?: string;
  derivation?: DerivationDescriptor;
  roles?: {
    identity?: boolean;
    funding?: boolean;
    ordinals?: boolean;
    encryption?: boolean;
  };
  shares?: { threshold: number; total: number; shareIds: string[] };
  metadata: Record<string, string>;
}

export interface LogLine {
  at: string;
  op: string;
  entryId?: string;
  reason?: string;
  caller?: string;
  ok: boolean;
  detail?: string;
}

export interface VaultDocument {
  version: 1;
  id: string;
  createdAt: string;
  updatedAt: string;
  settings: { revealEnabled: boolean; unlockTtlSeconds: number };
  entries: Entry[];
  log: LogLine[];
}

export const ENTRY_KINDS: EntryKind[] = [
  'entropy',
  'mnemonic',
  'hd-private',
  'hd-public',
  'private',
  'wif',
  'account',
  'share',
  'symmetric',
];

export const DERIVATION_SCHEMES = [
  'brc157',
  'bip32',
  'type42',
  'brc42',
  'legacy-bip32-unhardened',
] as const;

export function randomId(): string {
  return crypto.randomUUID();
}

export function isoNow(now?: () => number): string {
  return new Date(now ? now() : Date.now()).toISOString();
}

function fail(message: string): never {
  throw new Error(message);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function checkEntry(raw: unknown, index: number): Entry {
  if (!isRecord(raw)) fail(`entries[${index}]: must be an object`);
  if (typeof raw.id !== 'string' || raw.id.length === 0) fail(`entries[${index}]: bad id`);
  if (typeof raw.kind !== 'string' || !(ENTRY_KINDS as string[]).includes(raw.kind)) {
    fail(`entries[${index}]: unknown kind`);
  }
  if (typeof raw.label !== 'string') fail(`entries[${index}]: bad label`);
  if (!Array.isArray(raw.tags) || !raw.tags.every((t) => typeof t === 'string')) {
    fail(`entries[${index}]: bad tags`);
  }
  if (typeof raw.createdAt !== 'string' || typeof raw.updatedAt !== 'string') {
    fail(`entries[${index}]: bad timestamps`);
  }
  if (typeof raw.value !== 'string') fail(`entries[${index}]: bad value`);
  if (raw.publicKey !== undefined && typeof raw.publicKey !== 'string') {
    fail(`entries[${index}]: bad publicKey`);
  }
  if (raw.derivation !== undefined) {
    if (!isRecord(raw.derivation)) fail(`entries[${index}]: bad derivation`);
    const d = raw.derivation as Record<string, unknown>;
    if (
      typeof d.scheme !== 'string' ||
      !(DERIVATION_SCHEMES as readonly string[]).includes(d.scheme)
    ) {
      fail(`entries[${index}]: unknown derivation scheme`);
    }
    for (const key of ['path', 'parentIdentityKey', 'cohort'] as const) {
      if (d[key] !== undefined && typeof d[key] !== 'string')
        fail(`entries[${index}]: bad derivation.${key}`);
    }
    if (d.index !== undefined && typeof d.index !== 'number') {
      fail(`entries[${index}]: bad derivation.index`);
    }
  }
  if (raw.roles !== undefined) {
    if (!isRecord(raw.roles)) fail(`entries[${index}]: bad roles`);
    for (const key of ['identity', 'funding', 'ordinals', 'encryption'] as const) {
      const v = (raw.roles as Record<string, unknown>)[key];
      if (v !== undefined && typeof v !== 'boolean') fail(`entries[${index}]: bad roles.${key}`);
    }
  }
  if (raw.shares !== undefined) {
    if (!isRecord(raw.shares)) fail(`entries[${index}]: bad shares`);
    const s = raw.shares as Record<string, unknown>;
    if (
      typeof s.threshold !== 'number' ||
      typeof s.total !== 'number' ||
      !Array.isArray(s.shareIds)
    ) {
      fail(`entries[${index}]: bad shares`);
    }
    if (!(s.shareIds as unknown[]).every((v) => typeof v === 'string')) {
      fail(`entries[${index}]: bad shares.shareIds`);
    }
  }
  if (!isRecord(raw.metadata)) fail(`entries[${index}]: bad metadata`);
  for (const v of Object.values(raw.metadata as Record<string, unknown>)) {
    if (typeof v !== 'string') fail(`entries[${index}]: bad metadata value`);
  }
  return raw as unknown as Entry & { id: string; kind: EntryKind };
}

function checkLogLine(raw: unknown, index: number): LogLine {
  if (!isRecord(raw)) fail(`log[${index}]: must be an object`);
  if (typeof raw.at !== 'string' || typeof raw.op !== 'string' || typeof raw.ok !== 'boolean') {
    fail(`log[${index}]: bad required fields`);
  }
  for (const key of ['entryId', 'reason', 'caller', 'detail'] as const) {
    if (raw[key] !== undefined && typeof raw[key] !== 'string') fail(`log[${index}]: bad ${key}`);
  }
  return raw as unknown as LogLine;
}

export function validateDocument(value: unknown): VaultDocument {
  if (!isRecord(value)) fail('document must be an object');
  if (value.version !== 1) fail(`unsupported document version: ${String(value.version)}`);
  if (typeof value.id !== 'string' || value.id.length === 0) fail('document: bad id');
  if (typeof value.createdAt !== 'string' || typeof value.updatedAt !== 'string') {
    fail('document: bad timestamps');
  }
  if (!isRecord(value.settings)) fail('document: bad settings');
  const settings = value.settings as Record<string, unknown>;
  if (
    typeof settings.revealEnabled !== 'boolean' ||
    typeof settings.unlockTtlSeconds !== 'number'
  ) {
    fail('document: bad settings fields');
  }
  if (!Array.isArray(value.entries)) fail('document: bad entries');
  if (!Array.isArray(value.log)) fail('document: bad log');
  const entries = (value.entries as unknown[]).map((e, i) => checkEntry(e, i));
  const seen = new Set<string>();
  for (const e of entries) {
    if (seen.has(e.id)) fail(`duplicate entry id: ${e.id}`);
    seen.add(e.id);
  }
  for (const e of entries) {
    if (e.shares) {
      for (const ref of e.shares.shareIds) {
        if (!seen.has(ref)) fail(`entry ${e.id}: shares reference missing id ${ref}`);
      }
    }
  }
  for (const [i, line] of (value.log as unknown[]).entries()) checkLogLine(line, i);
  return value as unknown as VaultDocument;
}
