#!/usr/bin/env bun
import { spawnSync } from 'node:child_process';
import { existsSync, statSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { createInterface } from 'node:readline';
import { DeviceKeyProvider } from '../src/providers/device-p256.js';
import {
  EnclaveProvider,
  enclaveBinaryPath,
  isEnclaveSupported,
} from '../src/providers/enclave.js';
import { PassphraseProvider } from '../src/providers/passphrase.js';
import type { SealingProvider } from '../src/providers/provider.js';
import {
  addVaultSlot,
  createVault,
  defaultVaultPath,
  inspectVault,
  openVault,
  removeVaultSlot,
  saveVault,
} from '../src/store.js';
import { exportDocument, exportEncrypted, exportSealed, importEncrypted } from '../src/transfer.js';
import type { Vault } from '../src/vault.js';

const EXIT_OK = 0;
const EXIT_GENERIC = 1;
const EXIT_USAGE = 2;
const EXIT_LOCKED = 3;
const EXIT_NOTFOUND = 4;
const EXIT_REFUSED = 5;

class CliError extends Error {
  code: number;
  constructor(code: number, message: string) {
    super(message);
    this.code = code;
  }
}

function usageError(message: string): never {
  throw new CliError(EXIT_USAGE, message);
}

function lockedError(message: string): never {
  throw new CliError(EXIT_LOCKED, message);
}

function notFoundError(message: string): never {
  throw new CliError(EXIT_NOTFOUND, message);
}

const PASS_REFUSAL =
  'Refusing --passphrase on the command line: secrets never appear on argv (they stay visible in shell history and process listings). Use --passphrase-file <path>, --passphrase-stdin, or --passphrase-env <NAME> instead.';

interface Globals {
  json: boolean;
  vault?: string;
  reason?: string;
  passphraseFile?: string;
  passphraseStdin: boolean;
  passphraseEnv?: string;
  help: boolean;
}

function parseGlobals(argv: string[]): { globals: Globals; rest: string[] } {
  const globals: Globals = { json: false, passphraseStdin: false, help: false };
  const rest: string[] = [];
  let i = 0;
  while (i < argv.length) {
    const a = argv[i];
    if (a === '--') {
      rest.push(...argv.slice(i + 1));
      break;
    }
    if (a === '--passphrase' || a.startsWith('--passphrase=')) {
      throw new CliError(EXIT_USAGE, PASS_REFUSAL);
    }
    if (a === '--json') {
      globals.json = true;
      i += 1;
      continue;
    }
    if (a === '--help' || a === '-h') {
      globals.help = true;
      i += 1;
      continue;
    }
    if (a === '--passphrase-stdin') {
      globals.passphraseStdin = true;
      i += 1;
      continue;
    }
    if (
      a === '--vault' ||
      a === '--reason' ||
      a === '--passphrase-file' ||
      a === '--passphrase-env'
    ) {
      const v = argv[i + 1];
      if (v === undefined || v.startsWith('--')) usageError(`Missing value for ${a}`);
      if (a === '--vault') globals.vault = v;
      else if (a === '--reason') globals.reason = v;
      else if (a === '--passphrase-file') globals.passphraseFile = v;
      else globals.passphraseEnv = v;
      i += 2;
      continue;
    }
    if (a.startsWith('--vault=')) {
      globals.vault = a.slice('--vault='.length);
      i += 1;
      continue;
    }
    if (a.startsWith('--reason=')) {
      globals.reason = a.slice('--reason='.length);
      i += 1;
      continue;
    }
    if (a.startsWith('--passphrase-file=')) {
      globals.passphraseFile = a.slice('--passphrase-file='.length);
      i += 1;
      continue;
    }
    if (a.startsWith('--passphrase-env=')) {
      globals.passphraseEnv = a.slice('--passphrase-env='.length);
      i += 1;
      continue;
    }
    rest.push(a);
    i += 1;
  }
  return { globals, rest };
}

function vaultPathOf(globals: Globals): string {
  if (globals.vault !== undefined) {
    if (globals.vault.length === 0) usageError('--vault is set but empty');
    return globals.vault;
  }
  try {
    return defaultVaultPath();
  } catch (error) {
    throw new CliError(EXIT_USAGE, (error as Error).message);
  }
}

let stdinCache: string | null = null;
async function readAllStdin(): Promise<string> {
  if (stdinCache !== null) return stdinCache;
  try {
    stdinCache = await Bun.stdin.text();
  } catch {
    const chunks: Buffer[] = [];
    const stream = process.stdin;
    stream.setEncoding('utf8');
    for await (const chunk of stream) chunks.push(Buffer.from(chunk as string));
    stdinCache = Buffer.concat(chunks).toString('utf8');
  }
  return stdinCache;
}

function stripOneTrailingNewline(s: string): string {
  if (s.endsWith('\r\n')) return s.slice(0, -2);
  if (s.endsWith('\n')) return s.slice(0, -1);
  return s;
}

interface PassphraseSource {
  file?: string;
  stdin: boolean;
  env?: string;
}

/** Read a passphrase from exactly one non-argv source; null when none was given. */
async function readPassphraseFrom(src: PassphraseSource, label: string): Promise<string | null> {
  const n =
    (src.file !== undefined ? 1 : 0) + (src.stdin ? 1 : 0) + (src.env !== undefined ? 1 : 0);
  if (n > 1) usageError(`Only one ${label} source may be given (file, stdin, or env).`);
  if (src.file !== undefined) {
    let text: string;
    try {
      text = await readFile(src.file, 'utf8');
    } catch {
      lockedError(`Cannot read ${label} file: ${src.file}`);
    }
    const value = stripOneTrailingNewline(text as string);
    if (value.length === 0) lockedError(`${label} file is empty.`);
    return value;
  }
  if (src.stdin) {
    const value = stripOneTrailingNewline(await readAllStdin());
    if (value.length === 0) lockedError(`${label} on stdin is empty.`);
    return value;
  }
  if (src.env !== undefined) {
    if (src.env.length === 0) usageError(`${label} env option needs a variable name.`);
    const value = process.env[src.env];
    if (value === undefined) lockedError(`${label} env var ${src.env} is not set.`);
    if ((value as string).length === 0)
      lockedError(`${label} env var ${src.env} is set but empty.`);
    return value as string;
  }
  return null;
}

async function readPassphrase(globals: Globals): Promise<string | null> {
  return readPassphraseFrom(
    { file: globals.passphraseFile, stdin: globals.passphraseStdin, env: globals.passphraseEnv },
    'passphrase',
  );
}

type ExportPassphraseOpts = PassphraseSource;

function parseExportPassphraseOpts(args: string[]): ExportPassphraseOpts {
  const out: ExportPassphraseOpts = { stdin: false };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--export-passphrase-stdin') out.stdin = true;
    else if (a === '--export-passphrase-file') {
      const v = args[i + 1];
      if (v === undefined) usageError('Missing value for --export-passphrase-file');
      out.file = v;
      i += 1;
    } else if (a.startsWith('--export-passphrase-file=')) {
      out.file = a.slice('--export-passphrase-file='.length);
    } else if (a === '--export-passphrase-env') {
      const v = args[i + 1];
      if (v === undefined) usageError('Missing value for --export-passphrase-env');
      out.env = v;
      i += 1;
    } else if (a.startsWith('--export-passphrase-env=')) {
      out.env = a.slice('--export-passphrase-env='.length);
    } else if (a === '--export-passphrase' || a.startsWith('--export-passphrase=')) {
      throw new CliError(
        EXIT_USAGE,
        'Refusing --export-passphrase on the command line: secrets never appear on argv. Use --export-passphrase-file, --export-passphrase-stdin, or --export-passphrase-env instead.',
      );
    }
  }
  return out;
}

async function readExportPassphrase(opts: ExportPassphraseOpts): Promise<string | null> {
  return readPassphraseFrom(opts, 'export passphrase');
}

function promptLine(question: string): Promise<string> {
  return new Promise((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stderr });
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

async function ensureReason(globals: Globals, command: string): Promise<string> {
  if (globals.reason !== undefined) return globals.reason;
  if (globals.json) {
    usageError(
      `${command} requires --reason when --json is set (every unlock carries a reason for the audit log).`,
    );
  }
  if (process.stdin.isTTY) {
    const answer = (await promptLine('Reason for unlock: ')).trim();
    if (answer.length === 0) usageError(`${command} requires --reason.`);
    return answer;
  }
  usageError(`${command} requires --reason (not on a TTY, so it cannot be prompted).`);
}

async function ensurePassphraseOrThrow(globals: Globals, what: string): Promise<string> {
  const found = await readPassphrase(globals);
  if (found !== null) return found;
  if (process.stdin.isTTY) {
    const answer = stripOneTrailingNewline(await promptLine(`Passphrase for ${what}: `));
    if (answer.length === 0) lockedError('No passphrase given.');
    return answer;
  }
  lockedError(
    `No passphrase source given for ${what} and stdin is not a TTY. Use --passphrase-file <path>, --passphrase-stdin, or --passphrase-env <NAME>.`,
  );
}

async function resolveUnlockProvider(
  vaultPath: string,
  globals: Globals,
  what: string,
): Promise<{ provider: SealingProvider; passphrase: string | null }> {
  const passphrase = await readPassphrase(globals);
  if (passphrase !== null) {
    return { provider: new PassphraseProvider(passphrase), passphrase };
  }
  let slots: Array<{ type: string }> = [];
  try {
    slots = (await inspectVault(vaultPath)).slots;
  } catch (error) {
    const message = (error as Error).message;
    if (/vault not found|ENOENT/i.test(message)) throw new CliError(EXIT_NOTFOUND, message);
    throw error;
  }
  const hasPassphraseSlot = slots.some((s) => s.type === 'pbkdf2' || s.type === 'argon2id');
  const hasDeviceSlot = slots.some((s) => s.type === 'device-p256');
  if (!hasPassphraseSlot && hasDeviceSlot && isEnclaveSupported()) {
    return { provider: new EnclaveProvider('vault'), passphrase: null };
  }
  if (process.stdin.isTTY && hasPassphraseSlot) {
    const typed = stripOneTrailingNewline(await promptLine(`Passphrase for ${what}: `));
    if (typed.length === 0) lockedError('No passphrase given.');
    return { provider: new PassphraseProvider(typed), passphrase: typed };
  }
  lockedError(
    `No passphrase source given for ${what} and stdin is not a TTY. Use --passphrase-file <path>, --passphrase-stdin, or --passphrase-env <NAME>.`,
  );
}

async function openAndUnlock(
  vaultPath: string,
  globals: Globals,
  command: string,
): Promise<{ vault: Vault; provider: SealingProvider; passphrase: string | null; reason: string }> {
  const reason = await ensureReason(globals, command);
  const { provider, passphrase } = await resolveUnlockProvider(vaultPath, globals, command);
  let vault: Vault;
  try {
    vault = await openVault(vaultPath, provider);
  } catch (error) {
    const message = (error as Error).message;
    if (/vault not found|ENOENT/i.test(message)) throw new CliError(EXIT_NOTFOUND, message);
    throw new CliError(EXIT_LOCKED, `Cannot unlock vault: ${message}`);
  }
  vault.unlock(reason);
  return { vault, provider, passphrase, reason };
}

async function persist(vaultPath: string, vault: Vault, provider: SealingProvider): Promise<void> {
  try {
    await saveVault(vaultPath, vault, provider);
  } catch (error) {
    throw new CliError(EXIT_GENERIC, `Cannot save vault: ${(error as Error).message}`);
  }
}

function parseProtocol(spec: string): [0 | 1 | 2, string] {
  const idx = spec.indexOf(':');
  if (idx <= 0) usageError('--protocol must look like "<level>:<name>" (e.g. "2:vault test").');
  const level = Number(spec.slice(0, idx));
  const name = spec.slice(idx + 1);
  if ((level !== 0 && level !== 1 && level !== 2) || name.length === 0) {
    usageError('--protocol must look like "<level>:<name>" with level 0, 1, or 2.');
  }
  return [level as 0 | 1 | 2, name];
}

function hexToBytesStrict(hex: string, what: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex) || hex.length === 0) {
    usageError(`${what} must be hex.`);
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function emit(data: unknown): void {
  if (typeof data === 'string') {
    process.stdout.write(`${data}\n`);
    return;
  }
  process.stdout.write(`${JSON.stringify(data)}\n`);
}

function parseFlagValue(args: string[], names: string[]): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    for (const name of names) {
      if (a === name) {
        const v = args[i + 1];
        if (v === undefined) usageError(`Missing value for ${name}`);
        return v;
      }
      if (a.startsWith(`${name}=`)) return a.slice(name.length + 1);
    }
  }
  return undefined;
}

function hasFlag(args: string[], names: string[]): boolean {
  return args.some((a) => names.includes(a) || names.some((n) => a.startsWith(`${n}=`)));
}

function usageText(): string {
  return `vault — one encrypted document for every key

Usage: vault [--json] [--vault <path>] [--reason <text>] <command> [options]

Passphrase input (never on argv):
  --passphrase-file <path>   read passphrase from a file
  --passphrase-stdin         read passphrase from stdin
  --passphrase-env <NAME>    read passphrase from the named env var (verbatim)

Commands:
  init [--slot enclave|passphrase|device] [--allow-reveal=true|false]
  slot add [--slot enclave|passphrase|device] | slot remove <slot-id> | slot list
  list [--kind <kind>] [--tag <tag>] [--role <role>]
  import <file|-> [--label <label>]
  generate entropy|key|symmetric [--label <label>]
  derive <id> --scheme brc157 [--index N] [--label <label>]
  derive <id> --scheme brc42 --protocol "<level>:<name>" --key-id <key-id> [--counterparty <hex>] [--label <label>]
  pubkey <id> [--scheme brc42 --protocol ... --key-id ... --counterparty ...]
  sign <id> <data-hex|-> [--protocol ... --key-id ... --counterparty ...]
  shares split <id> -t <threshold> -n <total> [--label <label>]
  shares recover <share-id>... [--label <label>]
  export <id> --to-passphrase [--native] | --to-pubkey <hex>
  backup
  reveal <id> --reason "..."
  log [--since <ISO>]
  doctor
  completions bash|zsh|fish

Exit codes: 0 ok, 1 generic, 2 usage, 3 locked/auth failure, 4 not found, 5 refused by policy.`;
}

async function cmdInit(vaultPath: string, globals: Globals, args: string[]): Promise<void> {
  const slot = parseFlagValue(args, ['--slot']) ?? 'passphrase';
  if (slot !== 'passphrase' && slot !== 'enclave' && slot !== 'device') {
    usageError('init --slot must be enclave, passphrase, or device.');
  }
  let allowReveal = true;
  if (hasFlag(args, ['--allow-reveal'])) {
    const raw = parseFlagValue(args, ['--allow-reveal']);
    if (raw === undefined) allowReveal = true;
    else if (raw === 'true') allowReveal = true;
    else if (raw === 'false') allowReveal = false;
    else usageError('--allow-reveal must be true or false.');
  }
  if (existsSync(vaultPath)) {
    throw new CliError(EXIT_GENERIC, `Vault already exists: ${vaultPath}`);
  }
  if (slot === 'passphrase') {
    const passphrase = await ensurePassphraseOrThrow(globals, 'init');
    try {
      await createVault(vaultPath, [new PassphraseProvider(passphrase)], {
        revealEnabled: allowReveal,
      });
    } catch (error) {
      throw new CliError(EXIT_GENERIC, `Cannot create vault: ${(error as Error).message}`);
    }
  } else if (slot === 'enclave') {
    if (!isEnclaveSupported()) {
      throw new CliError(EXIT_GENERIC, 'Secure Enclave is not supported on this platform.');
    }
    try {
      await createVault(vaultPath, [new EnclaveProvider('vault')], {
        revealEnabled: allowReveal,
        allowSingleHardwareSlot: true,
      });
    } catch (error) {
      throw new CliError(EXIT_GENERIC, `Cannot create vault: ${(error as Error).message}`);
    }
    process.stderr.write(
      'Warning: vault has no passphrase recovery slot. Add one with: vault slot add --slot passphrase\n',
    );
  } else {
    const device = await DeviceKeyProvider.generate();
    try {
      await createVault(vaultPath, [device], {
        revealEnabled: allowReveal,
        allowSingleHardwareSlot: true,
      });
    } catch (error) {
      throw new CliError(EXIT_GENERIC, `Cannot create vault: ${(error as Error).message}`);
    }
    process.stderr.write(
      'Warning: device slot uses an ephemeral software key in this CLI preview; add a passphrase slot before quitting or the vault will be unopenable.\n',
    );
  }
  if (globals.json) emit({ path: vaultPath, slot, allowReveal });
  else process.stdout.write(`Initialized vault at ${vaultPath} with ${slot} slot\n`);
}

async function cmdSlot(vaultPath: string, globals: Globals, args: string[]): Promise<void> {
  const sub = args[0];
  if (sub === 'list' || sub === undefined) {
    let inspected: Awaited<ReturnType<typeof inspectVault>>;
    try {
      inspected = await inspectVault(vaultPath);
    } catch (error) {
      const message = (error as Error).message;
      if (/vault not found|ENOENT/i.test(message)) throw new CliError(EXIT_NOTFOUND, message);
      throw new CliError(EXIT_GENERIC, message);
    }
    if (globals.json) emit({ slots: inspected.slots });
    else {
      for (const s of inspected.slots) {
        process.stdout.write(`${s.id}\t${s.type}${s.publicKey ? `\t${s.publicKey}` : ''}\n`);
      }
    }
    return;
  }
  if (sub === 'add') {
    const rest = args.slice(1);
    const slotType = parseFlagValue(rest, ['--slot']) ?? 'passphrase';
    if (slotType !== 'passphrase' && slotType !== 'enclave' && slotType !== 'device') {
      usageError('slot add --slot must be enclave, passphrase, or device.');
    }
    const { provider } = await openAndUnlock(vaultPath, globals, 'slot add');
    let newProvider: SealingProvider;
    if (slotType === 'passphrase') {
      const news = parseExportPassphraseOpts(
        rest.flatMap((a) =>
          a.startsWith('--new-passphrase-file=')
            ? [`--export-passphrase-file=${a.slice('--new-passphrase-file='.length)}`]
            : a === '--new-passphrase-file'
              ? ['--export-passphrase-file']
              : a === '--new-passphrase-stdin'
                ? ['--export-passphrase-stdin']
                : a === '--new-passphrase-env'
                  ? ['--export-passphrase-env']
                  : a.startsWith('--new-passphrase-env=')
                    ? [`--export-passphrase-env=${a.slice('--new-passphrase-env='.length)}`]
                    : [a],
        ),
      );
      const explicit = await readExportPassphrase(news);
      if (explicit !== null) newProvider = new PassphraseProvider(explicit);
      else {
        const current = await readPassphrase(globals);
        if (current === null)
          usageError(
            'slot add --slot passphrase needs --new-passphrase-file, --new-passphrase-stdin, or --new-passphrase-env when the vault was unlocked without a passphrase.',
          );
        newProvider = new PassphraseProvider(current);
      }
    } else if (slotType === 'enclave') {
      if (!isEnclaveSupported())
        throw new CliError(EXIT_GENERIC, 'Secure Enclave is not supported on this platform.');
      newProvider = new EnclaveProvider('vault');
    } else {
      newProvider = await DeviceKeyProvider.generate();
      process.stderr.write(
        'Warning: device slot uses an ephemeral software key in this CLI preview.\n',
      );
    }
    try {
      const id = await addVaultSlot(vaultPath, provider, newProvider);
      if (globals.json) emit({ id, type: slotType });
      else process.stdout.write(`${id}\n`);
    } catch (error) {
      throw new CliError(EXIT_GENERIC, `Cannot add slot: ${(error as Error).message}`);
    }
    return;
  }
  if (sub === 'remove') {
    const rest = args.slice(1);
    const id = parseFlagValue(rest, ['--id']) ?? rest[0];
    if (!id) usageError('Usage: vault slot remove <slot-id>');
    const { provider } = await openAndUnlock(vaultPath, globals, 'slot remove');
    try {
      await removeVaultSlot(vaultPath, provider, id);
    } catch (error) {
      const message = (error as Error).message;
      if (/last slot/i.test(message)) throw new CliError(EXIT_REFUSED, message);
      if (/no slot|unknown/i.test(message)) throw new CliError(EXIT_NOTFOUND, message);
      throw new CliError(EXIT_GENERIC, message);
    }
    if (globals.json) emit({ removed: id });
    else process.stdout.write(`Removed slot ${id}\n`);
    return;
  }
  usageError('Usage: vault slot add|remove|list');
}

async function cmdList(vaultPath: string, globals: Globals, args: string[]): Promise<void> {
  const kind = parseFlagValue(args, ['--kind']);
  const tag = parseFlagValue(args, ['--tag']);
  const role = parseFlagValue(args, ['--role']);
  const { vault, provider } = await openAndUnlock(vaultPath, globals, 'list');
  const entries = vault.list({
    ...(kind === undefined ? {} : { kind: kind as never }),
    ...(tag === undefined ? {} : { tag }),
    ...(role === undefined ? {} : { role: role as never }),
  });
  await persist(vaultPath, vault, provider);
  if (globals.json) emit({ entries });
  else {
    for (const e of entries) {
      process.stdout.write(`${e.id}\t${e.kind}\t${e.label}\n`);
    }
  }
}

async function readImportSource(spec: string, passphraseOnStdin: boolean): Promise<string> {
  if (spec === '-') {
    if (passphraseOnStdin)
      usageError('Cannot read both the passphrase and the import file from stdin.');
    return readAllStdin();
  }
  try {
    return await readFile(spec, 'utf8');
  } catch {
    notFoundError(`Import file not found: ${spec}`);
  }
}

async function cmdImport(vaultPath: string, globals: Globals, args: string[]): Promise<void> {
  const file = args.find((a) => !a.startsWith('--'));
  if (!file) usageError('Usage: vault import <file|-> [--label <label>]');
  const label = parseFlagValue(args, ['--label']) ?? 'import';
  const content = await readImportSource(file, globals.passphraseStdin);
  const { vault, provider, passphrase } = await openAndUnlock(vaultPath, globals, 'import');
  let ids: string[];
  try {
    const unlock = passphrase !== null ? { passphrase } : { provider };
    const entries = await importEncrypted(vault, content, unlock as never, label);
    ids = entries.map((e) => e.id);
  } catch (error) {
    try {
      const payload = JSON.parse(content) as unknown;
      ids = vault.importPlain(payload, label).map((e) => e.id);
    } catch {
      throw new CliError(EXIT_GENERIC, `Cannot import: ${(error as Error).message}`);
    }
  }
  await persist(vaultPath, vault, provider);
  if (globals.json) emit({ imported: ids });
  else {
    for (const id of ids) process.stdout.write(`${id}\n`);
  }
}

async function cmdGenerate(vaultPath: string, globals: Globals, args: string[]): Promise<void> {
  const what = args.find((a) => !a.startsWith('--'));
  if (what !== 'entropy' && what !== 'key' && what !== 'symmetric') {
    usageError('Usage: vault generate entropy|key|symmetric [--label <label>]');
  }
  const label = parseFlagValue(args, ['--label']) ?? what;
  const { vault, provider } = await openAndUnlock(vaultPath, globals, 'generate');
  const entry =
    what === 'entropy'
      ? vault.generateEntropy(label)
      : what === 'key'
        ? vault.generateKey(label)
        : vault.generateSymmetric(label);
  await persist(vaultPath, vault, provider);
  if (globals.json) {
    const { value: _value, ...pub } = entry;
    emit({ entry: pub });
  } else process.stdout.write(`${entry.id}\n`);
}

async function cmdDerive(vaultPath: string, globals: Globals, args: string[]): Promise<void> {
  const tokens: string[] = [];
  const kv: Record<string, string> = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq >= 0) kv[a.slice(0, eq)] = a.slice(eq + 1);
      else if (
        ['--scheme', '--index', '--protocol', '--key-id', '--counterparty', '--label'].includes(a)
      ) {
        const v = args[i + 1];
        if (v === undefined) usageError(`Missing value for ${a}`);
        kv[a] = v;
        i += 1;
      } else {
        usageError(`Unknown flag for derive: ${a}`);
      }
    } else if (a.startsWith('-') && a.length > 1) {
      usageError(`Unknown flag for derive: ${a}`);
    } else tokens.push(a);
  }
  const id = tokens[0];
  if (!id)
    usageError(
      'Usage: vault derive <id> --scheme brc157 --index N | --scheme brc42 --protocol ... --key-id ...',
    );
  const scheme = kv['--scheme'];
  if (scheme !== 'brc157' && scheme !== 'brc42') {
    usageError('derive --scheme must be brc157 or brc42.');
  }
  const label = kv['--label'] ?? `derived ${scheme}`;
  const { vault, provider } = await openAndUnlock(vaultPath, globals, 'derive');
  try {
    if (scheme === 'brc157') {
      const rawIndex = kv['--index'];
      const index = rawIndex === undefined ? undefined : Number(rawIndex);
      if (rawIndex !== undefined && (!Number.isInteger(index) || (index as number) < 0)) {
        usageError('--index must be a non-negative integer.');
      }
      const entry = vault.derive(
        id,
        index === undefined ? { scheme: 'brc157' } : { scheme: 'brc157', index },
        label,
      );
      await persist(vaultPath, vault, provider);
      if (globals.json) {
        const { value: _value, ...pub } = entry;
        emit({ entry: pub });
      } else process.stdout.write(`${entry.id}\n`);
    } else {
      const protocolRaw = kv['--protocol'];
      const keyID = kv['--key-id'];
      if (!protocolRaw || !keyID)
        usageError(
          'derive --scheme brc42 needs --protocol "<level>:<name>" and --key-id <key-id>.',
        );
      const counterparty = kv['--counterparty'] ?? 'self';
      const entry = vault.derive(
        id,
        { scheme: 'brc42', brc42: { protocolID: parseProtocol(protocolRaw), keyID, counterparty } },
        label,
      );
      await persist(vaultPath, vault, provider);
      if (globals.json) {
        const { value: _value, ...pub } = entry;
        emit({ entry: pub });
      } else process.stdout.write(`${entry.id}\n`);
    }
  } catch (error) {
    if (error instanceof CliError) throw error;
    const message = (error as Error).message;
    if (/unknown entry/i.test(message)) throw new CliError(EXIT_NOTFOUND, message);
    if (/unsupported in this version/i.test(message)) throw new CliError(EXIT_REFUSED, message);
    throw new CliError(EXIT_GENERIC, message);
  }
}

async function cmdPubkey(vaultPath: string, globals: Globals, args: string[]): Promise<void> {
  const tokens: string[] = [];
  const kv: Record<string, string> = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq >= 0) kv[a.slice(0, eq)] = a.slice(eq + 1);
      else if (['--scheme', '--protocol', '--key-id', '--counterparty'].includes(a)) {
        const v = args[i + 1];
        if (v === undefined) usageError(`Missing value for ${a}`);
        kv[a] = v;
        i += 1;
      } else usageError(`Unknown flag for pubkey: ${a}`);
    } else tokens.push(a);
  }
  const id = tokens[0];
  if (!id) usageError('Usage: vault pubkey <id>');
  const { vault, provider } = await openAndUnlock(vaultPath, globals, 'pubkey');
  try {
    let key: string;
    if (
      kv['--protocol'] !== undefined ||
      kv['--key-id'] !== undefined ||
      kv['--scheme'] !== undefined
    ) {
      if (kv['--scheme'] !== 'brc42' || !kv['--protocol'] || !kv['--key-id']) {
        usageError('pubkey derivation needs --scheme brc42 --protocol ... --key-id ...');
      }
      key = vault.publicKey(id, {
        scheme: 'brc42',
        brc42: {
          protocolID: parseProtocol(kv['--protocol']),
          keyID: kv['--key-id'],
          counterparty: kv['--counterparty'] ?? 'self',
        },
      });
    } else {
      key = vault.publicKey(id);
    }
    await persist(vaultPath, vault, provider);
    if (globals.json) emit({ id, publicKey: key });
    else process.stdout.write(`${key}\n`);
  } catch (error) {
    if (error instanceof CliError) throw error;
    const message = (error as Error).message;
    if (/unknown entry/i.test(message)) throw new CliError(EXIT_NOTFOUND, message);
    throw new CliError(EXIT_GENERIC, message);
  }
}

async function readSignData(spec: string, passphraseOnStdin: boolean): Promise<Uint8Array> {
  const text =
    spec === '-'
      ? await (async () => {
          if (passphraseOnStdin)
            usageError('Cannot read both the passphrase and the sign data from stdin.');
          return stripOneTrailingNewline(await readAllStdin());
        })()
      : spec;
  const trimmed = text.trim();
  if (/^[0-9a-fA-F]*$/.test(trimmed) && trimmed.length > 0 && trimmed.length % 2 === 0) {
    return hexToBytesStrict(trimmed, 'sign data');
  }
  if (spec !== '-') usageError('sign data must be hex (or - for stdin).');
  return new TextEncoder().encode(text);
}

async function cmdSign(vaultPath: string, globals: Globals, args: string[]): Promise<void> {
  const tokens: string[] = [];
  const kv: Record<string, string> = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq >= 0) kv[a.slice(0, eq)] = a.slice(eq + 1);
      else if (['--protocol', '--key-id', '--counterparty'].includes(a)) {
        const v = args[i + 1];
        if (v === undefined) usageError(`Missing value for ${a}`);
        kv[a] = v;
        i += 1;
      } else usageError(`Unknown flag for sign: ${a}`);
    } else tokens.push(a);
  }
  const id = tokens[0];
  const dataSpec = tokens[1];
  if (!id || !dataSpec)
    usageError('Usage: vault sign <id> <data-hex|-> [--protocol ... --key-id ...]');
  if ((kv['--protocol'] === undefined) !== (kv['--key-id'] === undefined)) {
    usageError('sign needs both --protocol and --key-id, or neither.');
  }
  const { vault, provider } = await openAndUnlock(vaultPath, globals, 'sign');
  try {
    const data = await readSignData(dataSpec, globals.passphraseStdin);
    const spec =
      kv['--protocol'] !== undefined
        ? {
            scheme: 'brc42' as const,
            brc42: {
              protocolID: parseProtocol(kv['--protocol']),
              keyID: kv['--key-id'] as string,
              counterparty: kv['--counterparty'] ?? 'self',
            },
          }
        : undefined;
    const signer = vault.signer(id, spec);
    const sig = await signer.sign(data);
    await persist(vaultPath, vault, provider);
    const hex = bytesToHex(sig);
    if (globals.json) emit({ id, signature: hex });
    else process.stdout.write(`${hex}\n`);
  } catch (error) {
    if (error instanceof CliError) throw error;
    const message = (error as Error).message;
    if (/unknown entry/i.test(message)) throw new CliError(EXIT_NOTFOUND, message);
    if (/SessionExpired|roots do not sign|profile roots sign only/i.test(message)) {
      throw new CliError(EXIT_REFUSED, message);
    }
    throw new CliError(EXIT_GENERIC, message);
  }
}

async function cmdShares(vaultPath: string, globals: Globals, args: string[]): Promise<void> {
  const sub = args[0];
  if (sub === 'split') {
    const rest = args.slice(1);
    const tokens: string[] = [];
    const kv: Record<string, string> = {};
    for (let i = 0; i < rest.length; i++) {
      const a = rest[i];
      if (a === '-t' || a === '--threshold') {
        const v = rest[i + 1];
        if (v === undefined) usageError('Missing value for -t/--threshold');
        kv['-t'] = v;
        i += 1;
      } else if (a === '-n' || a === '--total') {
        const v = rest[i + 1];
        if (v === undefined) usageError('Missing value for -n/--total');
        kv['-n'] = v;
        i += 1;
      } else if (a === '--label') {
        const v = rest[i + 1];
        if (v === undefined) usageError('Missing value for --label');
        kv['--label'] = v;
        i += 1;
      } else if (a.startsWith('--label=')) kv['--label'] = a.slice('--label='.length);
      else if (a.startsWith('-')) usageError(`Unknown flag for shares split: ${a}`);
      else tokens.push(a);
    }
    const id = tokens[0];
    if (!id) usageError('Usage: vault shares split <id> -t <threshold> -n <total>');
    const t = Number(kv['-t']);
    const n = Number(kv['-n']);
    if (!Number.isInteger(t) || !Number.isInteger(n)) usageError('-t and -n must be integers.');
    const { vault, provider } = await openAndUnlock(vaultPath, globals, 'shares split');
    try {
      const shares = vault.split(id, t, n);
      await persist(vaultPath, vault, provider);
      const ids = shares.map((s) => s.id);
      if (globals.json) emit({ source: id, threshold: t, total: n, shares: ids });
      else {
        for (const shareId of ids) process.stdout.write(`${shareId}\n`);
      }
    } catch (error) {
      throw new CliError(EXIT_GENERIC, (error as Error).message);
    }
    return;
  }
  if (sub === 'recover') {
    const rest = args.slice(1);
    const tokens: string[] = [];
    let label = 'recovered';
    for (let i = 0; i < rest.length; i++) {
      const a = rest[i];
      if (a === '--label') {
        const v = rest[i + 1];
        if (v === undefined) usageError('Missing value for --label');
        label = v;
        i += 1;
      } else if (a.startsWith('--label=')) label = a.slice('--label='.length);
      else if (a.startsWith('-')) usageError(`Unknown flag for shares recover: ${a}`);
      else tokens.push(a);
    }
    if (tokens.length === 0)
      usageError('Usage: vault shares recover <share-id>... [--label <label>]');
    const { vault, provider } = await openAndUnlock(vaultPath, globals, 'shares recover');
    try {
      const entry = vault.recover(tokens, label);
      await persist(vaultPath, vault, provider);
      if (globals.json) {
        const { value: _value, ...pub } = entry;
        emit({ entry: pub });
      } else process.stdout.write(`${entry.id}\n`);
    } catch (error) {
      throw new CliError(EXIT_GENERIC, (error as Error).message);
    }
    return;
  }
  usageError('Usage: vault shares split <id> -t N -n M | vault shares recover <share-id>...');
}

async function cmdExport(vaultPath: string, globals: Globals, args: string[]): Promise<void> {
  const tokens: string[] = [];
  const kv: Record<string, string> = {};
  let toPassphrase = false;
  let native = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--to-passphrase') toPassphrase = true;
    else if (a === '--native') native = true;
    else if (a === '--to-pubkey') {
      const v = args[i + 1];
      if (v === undefined) usageError('Missing value for --to-pubkey');
      kv['--to-pubkey'] = v;
      i += 1;
    } else if (a.startsWith('--to-pubkey=')) kv['--to-pubkey'] = a.slice('--to-pubkey='.length);
    else if (
      a === '--export-passphrase-file' ||
      a === '--export-passphrase-env' ||
      a.startsWith('--export-passphrase-file=') ||
      a.startsWith('--export-passphrase-env=') ||
      a === '--export-passphrase-stdin'
    ) {
    } else if (a.startsWith('--')) usageError(`Unknown flag for export: ${a}`);
    else tokens.push(a);
  }
  const id = tokens[0];
  if (!id) usageError('Usage: vault export <id> --to-passphrase [--native] | --to-pubkey <hex>');
  const toPubkey = kv['--to-pubkey'];
  if ((toPassphrase ? 1 : 0) + (toPubkey !== undefined ? 1 : 0) !== 1) {
    usageError('export needs exactly one of --to-passphrase or --to-pubkey <hex>.');
  }
  const { vault, provider, passphrase } = await openAndUnlock(vaultPath, globals, 'export');
  try {
    if (toPubkey !== undefined) {
      process.stderr.write(
        'Warning: sealed export duplicates authority; the recipient gains independent control. This is not custody transfer.\n',
      );
      const wrapped = await exportSealed(vault, id, toPubkey);
      await persist(vaultPath, vault, provider);
      const b64 = Buffer.from(wrapped).toString('base64');
      if (globals.json) emit({ id, format: 'sealed', to: toPubkey, data: b64 });
      else process.stdout.write(`${b64}\n`);
      return;
    }
    const exportOpts = parseExportPassphraseOpts(args);
    let exportPass = await readExportPassphrase(exportOpts);
    if (exportPass === null) {
      if (passphrase !== null) exportPass = passphrase;
      else if (process.stdin.isTTY) {
        exportPass = stripOneTrailingNewline(await promptLine('Passphrase for exported file: '));
        if (exportPass.length === 0) lockedError('No export passphrase given.');
      } else {
        lockedError(
          'No export passphrase source given and stdin is not a TTY. Use --export-passphrase-file, --export-passphrase-stdin, or --export-passphrase-env.',
        );
      }
    }
    const bep = await exportEncrypted(
      vault,
      id,
      exportPass as string,
      native ? { as: 'native' } : {},
    );
    await persist(vaultPath, vault, provider);
    if (globals.json) emit({ id, format: native ? 'native' : 'entry', bep });
    else process.stdout.write(`${bep}\n`);
  } catch (error) {
    if (error instanceof CliError) throw error;
    const message = (error as Error).message;
    if (/unknown entry/i.test(message)) throw new CliError(EXIT_NOTFOUND, message);
    if (/no native export form/i.test(message)) throw new CliError(EXIT_REFUSED, message);
    throw new CliError(EXIT_GENERIC, message);
  }
}

async function cmdBackup(vaultPath: string, globals: Globals, args: string[]): Promise<void> {
  for (const a of args) {
    if (
      a.startsWith('--') &&
      a !== '--export-passphrase-stdin' &&
      !a.startsWith('--export-passphrase-file') &&
      !a.startsWith('--export-passphrase-env')
    ) {
      usageError(`Unknown flag for backup: ${a}`);
    }
  }
  const { vault, provider, passphrase } = await openAndUnlock(vaultPath, globals, 'backup');
  const exportOpts = parseExportPassphraseOpts(args);
  let backupPass = await readExportPassphrase(exportOpts);
  if (backupPass === null) {
    if (passphrase !== null) backupPass = passphrase;
    else if (process.stdin.isTTY) {
      backupPass = stripOneTrailingNewline(await promptLine('Passphrase for backup file: '));
      if (backupPass.length === 0) lockedError('No backup passphrase given.');
    } else {
      lockedError(
        'No backup passphrase source given and stdin is not a TTY. Use --export-passphrase-file, --export-passphrase-stdin, or --export-passphrase-env.',
      );
    }
  }
  const bep = await exportDocument(vault, backupPass as string);
  await persist(vaultPath, vault, provider);
  if (globals.json) emit({ bep });
  else process.stdout.write(`${bep}\n`);
}

async function cmdReveal(vaultPath: string, globals: Globals, args: string[]): Promise<void> {
  const tokens = args.filter((a) => !a.startsWith('--'));
  for (const a of args) {
    if (a.startsWith('--')) usageError(`Unknown flag for reveal: ${a} (use global --reason "...")`);
  }
  const id = tokens[0];
  if (!id) usageError('Usage: vault reveal <id> --reason "..."');
  const { vault, provider, reason } = await openAndUnlock(vaultPath, globals, 'reveal');
  try {
    const value = vault.reveal(id, reason);
    await persist(vaultPath, vault, provider);
    if (globals.json) emit({ id, value });
    else process.stdout.write(`${value}\n`);
  } catch (error) {
    if (error instanceof CliError) throw error;
    const message = (error as Error).message;
    if (/unknown entry/i.test(message)) throw new CliError(EXIT_NOTFOUND, message);
    if (/reveal is disabled/i.test(message)) {
      try {
        await persist(vaultPath, vault, provider);
      } catch {
        // The refusal matters more than a save failure; report the refusal.
      }
      throw new CliError(EXIT_REFUSED, message);
    }
    throw new CliError(EXIT_GENERIC, message);
  }
}

async function cmdLog(vaultPath: string, globals: Globals, args: string[]): Promise<void> {
  const since = parseFlagValue(args, ['--since']);
  for (const a of args) {
    if (a.startsWith('--') && a !== '--since' && !a.startsWith('--since=')) {
      usageError(`Unknown flag for log: ${a}`);
    }
  }
  const { vault, provider } = await openAndUnlock(vaultPath, globals, 'log');
  const lines = vault.toDocument().log.filter((l) => since === undefined || l.at >= since);
  await persist(vaultPath, vault, provider);
  if (globals.json) emit({ log: lines });
  else {
    for (const l of lines) {
      process.stdout.write(
        `${l.at}\t${l.op}\t${l.entryId ?? ''}\t${l.reason ?? ''}\t${l.ok ? 'ok' : 'fail'}\t${l.detail ?? ''}\n`,
      );
    }
  }
}

function checkEnclave(): { supported: boolean; binaryPresent: boolean; check: string } {
  const supported = isEnclaveSupported();
  const binaryPresent = existsSync(enclaveBinaryPath());
  let check = 'not run';
  if (supported && binaryPresent) {
    try {
      const result = spawnSync(enclaveBinaryPath(), ['check'], { encoding: 'utf8', timeout: 5000 });
      const out = String(result.stdout ?? '').trim();
      if (out.length > 0) {
        try {
          const parsed = JSON.parse(out) as { success?: boolean; error?: string };
          check = parsed.success ? 'available' : `unavailable: ${parsed.error ?? 'check failed'}`;
        } catch {
          check = out.slice(0, 200);
        }
      } else if (result.error) {
        check = `unavailable: ${(result.error as Error).message}`;
      } else {
        check = `exit ${String(result.status)}`;
      }
    } catch (error) {
      check = `unavailable: ${(error as Error).message}`;
    }
  } else if (!supported) {
    check = 'unsupported platform';
  } else {
    check = 'helper binary missing';
  }
  return { supported, binaryPresent, check };
}

async function cmdDoctor(vaultPath: string, globals: Globals): Promise<void> {
  const platform = `${process.platform}/${process.arch}`;
  const enclave = checkEnclave();
  const exists = existsSync(vaultPath);
  let mode: string | null = null;
  let slots: Array<{ id: string; type: string; publicKey?: string }> = [];
  if (exists) {
    try {
      const st = statSync(vaultPath);
      mode = (st.mode & 0o777).toString(8).padStart(4, '0');
    } catch {
      mode = null;
    }
    try {
      slots = (await inspectVault(vaultPath)).slots.map((s) => ({
        id: s.id,
        type: s.type,
        ...(s.publicKey === undefined ? {} : { publicKey: s.publicKey }),
      }));
    } catch (error) {
      throw new CliError(EXIT_GENERIC, `Cannot inspect vault: ${(error as Error).message}`);
    }
  }
  const pbkdf2Present = slots.some((s) => s.type === 'pbkdf2');
  const argon2idPresent = slots.some((s) => s.type === 'argon2id');
  const devicePresent = slots.some((s) => s.type === 'device-p256');
  const recoveryPresent = pbkdf2Present || argon2idPresent;
  const report = {
    platform,
    enclaveSupported: enclave.supported,
    enclaveBinaryPresent: enclave.binaryPresent,
    enclaveCheck: enclave.check,
    vaultPath,
    exists,
    mode,
    slots,
    pbkdf2Present,
    argon2idPresent,
    devicePresent,
    recoveryPresent,
  };
  if (globals.json) emit(report);
  else {
    process.stdout.write(`platform: ${platform}\n`);
    process.stdout.write(
      `enclave: supported=${String(enclave.supported)} binary=${String(enclave.binaryPresent)} check=${enclave.check}\n`,
    );
    process.stdout.write(`vault: ${vaultPath} exists=${String(exists)} mode=${mode ?? 'n/a'}\n`);
    process.stdout.write(
      `slots: argon2id=${String(argon2idPresent)} pbkdf2=${String(pbkdf2Present)} device-p256=${String(devicePresent)} recovery=${String(recoveryPresent)}\n`,
    );
    for (const s of slots) {
      process.stdout.write(`  ${s.id} ${s.type}\n`);
    }
  }
}

function completionsFor(shell: string): string {
  const commands =
    'init slot list import generate derive pubkey sign shares export backup reveal log doctor completions';
  if (shell === 'bash') {
    return `\
_vault_complete() {
  local cur="\${COMP_WORDS[COMP_CWORD]}"
  local cmds="${commands}"
  COMPREPLY=( $(compgen -W "$cmds" -- "$cur") )
}
complete -F _vault_complete vault
`;
  }
  if (shell === 'zsh') {
    return `\
#compdef vault
_vault() {
  local -a cmds
  cmds=(${commands
    .split(' ')
    .map((c) => `'${c}'`)
    .join(' ')});
  _describe 'vault commands' cmds
}
_vault
`;
  }
  return `\
# fish completion for vault
for cmd in ${commands};
  complete -c vault -n '__fish_use_subcommand' -f -a $cmd
end
`;
}

async function main(): Promise<void> {
  try {
    const raw = process.argv.slice(2);
    const { globals, rest } = parseGlobals(raw);
    const [command, ...args] = rest;
    if (globals.help || command === undefined || command === 'help') {
      process.stdout.write(`${usageText()}\n`);
      process.exit(EXIT_OK);
    }
    if (command === 'completions') {
      const shell = args[0];
      if (shell !== 'bash' && shell !== 'zsh' && shell !== 'fish') {
        usageError('Usage: vault completions bash|zsh|fish');
      }
      process.stdout.write(completionsFor(shell));
      process.exit(EXIT_OK);
    }
    const vaultPath = vaultPathOf(globals);
    switch (command) {
      case 'init':
        await cmdInit(vaultPath, globals, args);
        break;
      case 'slot':
        await cmdSlot(vaultPath, globals, args);
        break;
      case 'list':
        await cmdList(vaultPath, globals, args);
        break;
      case 'import':
        await cmdImport(vaultPath, globals, args);
        break;
      case 'generate':
        await cmdGenerate(vaultPath, globals, args);
        break;
      case 'derive':
        await cmdDerive(vaultPath, globals, args);
        break;
      case 'pubkey':
        await cmdPubkey(vaultPath, globals, args);
        break;
      case 'sign':
        await cmdSign(vaultPath, globals, args);
        break;
      case 'shares':
        await cmdShares(vaultPath, globals, args);
        break;
      case 'export':
        await cmdExport(vaultPath, globals, args);
        break;
      case 'backup':
        await cmdBackup(vaultPath, globals, args);
        break;
      case 'reveal':
        await cmdReveal(vaultPath, globals, args);
        break;
      case 'log':
        await cmdLog(vaultPath, globals, args);
        break;
      case 'doctor':
        await cmdDoctor(vaultPath, globals);
        break;
      default:
        usageError(`Unknown command: ${command}\n${usageText()}`);
    }
    process.exit(EXIT_OK);
  } catch (error) {
    if (error instanceof CliError) {
      process.stderr.write(`${(error as Error).message}\n`);
      process.exit((error as CliError).code);
    }
    process.stderr.write(`${(error as Error).message}\n`);
    process.exit(EXIT_GENERIC);
  }
}

await main();
