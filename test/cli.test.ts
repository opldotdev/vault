import { beforeAll, expect, test } from 'bun:test';
import { mkdtempSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PublicKey, Signature } from '@bsv/sdk';

const CLI = new URL('../dist/cli/vault.js', import.meta.url).pathname;
const PASS = 'correct horse battery staple';
const REASON = 'cli-test';

beforeAll(async () => {
  const proc = Bun.spawn(['bun', 'run', 'build'], { stdout: 'pipe', stderr: 'pipe' });
  const code = await proc.exited;
  if (code !== 0) {
    const err = await new Response(proc.stderr).text();
    throw new Error(`bun run build failed:\n${err}`);
  }
}, 120_000);

interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

async function run(
  args: string[],
  opts: { stdin?: string; env?: Record<string, string> } = {},
): Promise<RunResult> {
  const proc = Bun.spawn(['bun', CLI, ...args], {
    stdin: opts.stdin !== undefined ? new Response(opts.stdin) : 'ignore',
    stdout: 'pipe',
    stderr: 'pipe',
    env: { ...(process.env as Record<string, string>), ...opts.env },
  });
  const [stdout, stderr, code] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);
  return { code, stdout, stderr };
}

function setupVault(): { vault: string; passFile: string } {
  const dir = mkdtempSync(join(tmpdir(), 'vault-cli-'));
  const vault = join(dir, 'vault.bep');
  const passFile = join(dir, 'pass.txt');
  writeFileSync(passFile, PASS, { mode: 0o600 });
  return { vault, passFile };
}

function base(vault: string, passFile: string): string[] {
  return ['--vault', vault, '--passphrase-file', passFile, '--reason', REASON, '--json'];
}

async function initVault(vault: string, passFile: string, extra: string[] = []): Promise<void> {
  const r = await run([
    '--vault',
    vault,
    'init',
    '--slot',
    'passphrase',
    '--passphrase-file',
    passFile,
    ...extra,
  ]);
  expect(r.code).toBe(0);
}

test('init creates a passphrase vault from a file', async () => {
  const { vault, passFile } = setupVault();
  const r = await run([
    '--vault',
    vault,
    'init',
    '--slot',
    'passphrase',
    '--passphrase-file',
    passFile,
  ]);
  expect(r.code).toBe(0);
  expect(statSync(vault).mode & 0o777).toBe(0o600);
  expect(r.stderr).not.toContain(PASS);
}, 30_000);

test('generate entropy then derive brc157 index 1', async () => {
  const { vault, passFile } = setupVault();
  await initVault(vault, passFile);
  const g = await run([...base(vault, passFile), 'generate', 'entropy', '--label', 'root']);
  expect(g.code).toBe(0);
  const root = JSON.parse(g.stdout).entry;
  expect(root.kind).toBe('entropy');
  expect('value' in root).toBe(false);
  const d = await run([
    ...base(vault, passFile),
    'derive',
    root.id,
    '--scheme',
    'brc157',
    '--index',
    '1',
  ]);
  expect(d.code).toBe(0);
  const child = JSON.parse(d.stdout).entry;
  expect(child.id).not.toBe(root.id);
  expect(child.derivation).toMatchObject({ scheme: 'brc157', index: 1 });
  expect('value' in child).toBe(false);
}, 30_000);

test('pubkey and sign verify with the SDK', async () => {
  const { vault, passFile } = setupVault();
  await initVault(vault, passFile);
  const g = await run([...base(vault, passFile), 'generate', 'entropy', '--label', 'root']);
  const rootId = JSON.parse(g.stdout).entry.id as string;
  const d = await run([
    ...base(vault, passFile),
    'derive',
    rootId,
    '--scheme',
    'brc157',
    '--index',
    '1',
  ]);
  const childId = JSON.parse(d.stdout).entry.id as string;
  const p = await run([
    ...base(vault, passFile),
    'pubkey',
    childId,
    '--scheme',
    'brc42',
    '--protocol',
    '2:vault test',
    '--key-id',
    'k1',
  ]);
  expect(p.code).toBe(0);
  const pubkey = JSON.parse(p.stdout).publicKey as string;
  expect(pubkey).toHaveLength(66);
  const dataHex = Buffer.from('hello vault').toString('hex');
  const s = await run([
    ...base(vault, passFile),
    'sign',
    childId,
    dataHex,
    '--protocol',
    '2:vault test',
    '--key-id',
    'k1',
  ]);
  expect(s.code).toBe(0);
  const sigHex = JSON.parse(s.stdout).signature as string;
  const ok = PublicKey.fromString(pubkey).verify(
    Array.from(Uint8Array.from(Buffer.from(dataHex, 'hex'))),
    Signature.fromDER(Array.from(Uint8Array.from(Buffer.from(sigHex, 'hex')))),
  );
  expect(ok).toBe(true);
}, 60_000);

test('shares split then recover', async () => {
  const { vault, passFile } = setupVault();
  await initVault(vault, passFile);
  const g = await run([...base(vault, passFile), 'generate', 'entropy', '--label', 'root']);
  const rootId = JSON.parse(g.stdout).entry.id as string;
  const sp = await run([...base(vault, passFile), 'shares', 'split', rootId, '-t', '2', '-n', '3']);
  expect(sp.code).toBe(0);
  const shareIds = JSON.parse(sp.stdout).shares as string[];
  expect(shareIds).toHaveLength(3);
  const rc = await run([
    ...base(vault, passFile),
    'shares',
    'recover',
    shareIds[0],
    shareIds[2],
    '--label',
    'recovered',
  ]);
  expect(rc.code).toBe(0);
  const recoveredId = JSON.parse(rc.stdout).entry.id as string;
  // Sequential: the vault file takes an exclusive lock per process.
  const a = await run([...base(vault, passFile), 'reveal', rootId]);
  const b = await run([...base(vault, passFile), 'reveal', recoveredId]);
  expect(a.code).toBe(0);
  expect(b.code).toBe(0);
  expect(JSON.parse(b.stdout).value).toBe(JSON.parse(a.stdout).value);
}, 60_000);

test('export and import round trip', async () => {
  const { vault, passFile } = setupVault();
  await initVault(vault, passFile);
  const g = await run([...base(vault, passFile), 'generate', 'key', '--label', 'k']);
  const keyId = JSON.parse(g.stdout).entry.id as string;
  const ex = await run([...base(vault, passFile), 'export', keyId, '--to-passphrase']);
  expect(ex.code).toBe(0);
  const bep = JSON.parse(ex.stdout).bep as string;
  expect(typeof bep).toBe('string');
  const bepFile = join(tmpdir(), `vault-cli-export-${process.pid}-${Date.now()}.bep`);
  writeFileSync(bepFile, bep);
  const im = await run([...base(vault, passFile), 'import', bepFile, '--label', 'reimported']);
  expect(im.code).toBe(0);
  const importedId = (JSON.parse(im.stdout).imported as string[])[0];
  expect(importedId).not.toBe(keyId);
  // Sequential: the vault file takes an exclusive lock per process.
  const a = await run([...base(vault, passFile), 'reveal', keyId]);
  const b = await run([...base(vault, passFile), 'reveal', importedId]);
  expect(JSON.parse(b.stdout).value).toBe(JSON.parse(a.stdout).value);
}, 60_000);

test('reveal is logged and refused when the vault disables it', async () => {
  const { vault, passFile } = setupVault();
  await initVault(vault, passFile, ['--allow-reveal=false']);
  const g = await run([...base(vault, passFile), 'generate', 'key', '--label', 'k']);
  const keyId = JSON.parse(g.stdout).entry.id as string;
  const r = await run([...base(vault, passFile), 'reveal', keyId]);
  expect(r.code).toBe(5);
  expect(r.stdout).not.toContain('value');
  const log = await run([...base(vault, passFile), 'log']);
  expect(log.code).toBe(0);
  const lines = JSON.parse(log.stdout).log as Array<{
    op: string;
    entryId?: string;
    ok: boolean;
  }>;
  expect(lines.some((l) => l.op === 'reveal' && l.entryId === keyId && l.ok === false)).toBe(true);
}, 60_000);

test('doctor --json emits one object', async () => {
  const { vault, passFile } = setupVault();
  await initVault(vault, passFile);
  const d = await run(['--vault', vault, 'doctor', '--json']);
  expect(d.code).toBe(0);
  const report = JSON.parse(d.stdout) as Record<string, unknown>;
  expect(report.vaultPath).toBe(vault);
  expect(report.exists).toBe(true);
  expect(report.mode).toBe('0600');
  expect(report.pbkdf2Present).toBe(true);
  expect(report.recoveryPresent).toBe(true);
  expect(report.slots).toHaveLength(1);
  expect(typeof report.platform).toBe('string');
}, 30_000);

test('--passphrase on argv exits 2', async () => {
  const r = await run(['--vault', '/tmp/does-not-matter.bep', '--passphrase', 'secret', 'list']);
  expect(r.code).toBe(2);
  expect(r.stderr).toMatch(/Refusing --passphrase/);
}, 30_000);

test('completions prints a shell script', async () => {
  const r = await run(['completions', 'bash']);
  expect(r.code).toBe(0);
  expect(r.stdout).toContain('vault');
}, 30_000);
