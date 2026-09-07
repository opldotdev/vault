import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { type VaultDocument, validateDocument } from '../src/document.js';

function fixture(): VaultDocument {
  return {
    version: 1,
    id: 'doc-1',
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
    settings: { revealEnabled: true, unlockTtlSeconds: 300 },
    entries: [
      {
        id: 'e1',
        kind: 'entropy',
        label: 'root',
        tags: ['a'],
        createdAt: '2026-01-01T00:00:00.000Z',
        updatedAt: '2026-01-01T00:00:00.000Z',
        value: `${'00'.repeat(31)}01`,
        metadata: {},
      },
    ],
    log: [{ at: '2026-01-01T00:00:00.000Z', op: 'generate', entryId: 'e1', ok: true }],
  };
}

type Schema = Record<string, unknown>;

function check(schema: Schema, value: unknown, path = '$'): string[] {
  const errors: string[] = [];
  const type = schema.type as string | undefined;
  if (schema.const !== undefined && JSON.stringify(value) !== JSON.stringify(schema.const)) {
    errors.push(`${path}: expected const ${JSON.stringify(schema.const)}`);
    return errors;
  }
  if (schema.enum && !(schema.enum as unknown[]).includes(value)) {
    errors.push(`${path}: not in enum`);
    return errors;
  }
  if (type === 'object') {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      return [`${path}: expected object`];
    }
    const rec = value as Record<string, unknown>;
    for (const key of (schema.required as string[] | undefined) ?? []) {
      if (!(key in rec)) errors.push(`${path}: missing ${key}`);
    }
    const props = (schema.properties as Record<string, Schema> | undefined) ?? {};
    for (const [key, prop] of Object.entries(props)) {
      if (key in rec) errors.push(...check(resolve(prop), rec[key], `${path}.${key}`));
    }
    return errors;
  }
  if (type === 'array') {
    if (!Array.isArray(value)) return [`${path}: expected array`];
    const items = schema.items as Schema | undefined;
    if (items) {
      for (const [i, v] of value.entries()) {
        errors.push(...check(resolve(items), v, `${path}[${i}]`));
      }
    }
    return errors;
  }
  if (type === 'integer') {
    if (typeof value !== 'number' || !Number.isInteger(value))
      errors.push(`${path}: expected integer`);
    return errors;
  }
  if (type === 'number' || type === 'string' || type === 'boolean') {
    if (typeof value !== type) errors.push(`${path}: expected ${type}`);
    return errors;
  }
  if (schema.$ref) return check(resolve(schema), value, path);
  return errors;
}

const rootSchema = JSON.parse(
  readFileSync(new URL('../schema/vault-document.schema.json', import.meta.url), 'utf8'),
) as Schema;

function resolve(schema: Schema): Schema {
  if (schema.$ref && typeof schema.$ref === 'string' && schema.$ref.startsWith('#/')) {
    const parts = schema.$ref.slice(2).split('/');
    let node: unknown = rootSchema;
    for (const part of parts) node = (node as Record<string, unknown>)[part];
    return node as Schema;
  }
  return schema;
}

describe('document', () => {
  test('fixture validates against the JSON schema', () => {
    expect(check(rootSchema, fixture())).toEqual([]);
  });

  test('fixture passes validateDocument', () => {
    expect(validateDocument(fixture()).id).toBe('doc-1');
  });

  test('rejects unknown version', () => {
    expect(() => validateDocument({ ...fixture(), version: 2 })).toThrow();
  });

  test('rejects unknown kind', () => {
    const doc = fixture();
    doc.entries[0].kind = 'nope' as never;
    expect(() => validateDocument(doc)).toThrow();
  });

  test('rejects duplicate ids', () => {
    const doc = fixture();
    doc.entries.push({ ...doc.entries[0] });
    expect(() => validateDocument(doc)).toThrow(/duplicate/);
  });

  test('rejects shares referencing a missing id', () => {
    const doc = fixture();
    doc.entries[0].shares = { threshold: 2, total: 3, shareIds: ['missing'] };
    expect(() => validateDocument(doc)).toThrow(/missing/);
  });

  test('accepts shares referencing an existing id', () => {
    const doc = fixture();
    doc.entries.push({
      ...doc.entries[0],
      id: 'share-1',
      kind: 'share',
      value: 'share-string',
    });
    doc.entries[0].shares = { threshold: 1, total: 1, shareIds: ['share-1'] };
    expect(validateDocument(doc).entries).toHaveLength(2);
  });
});
