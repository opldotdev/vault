# @opl.dev/vault

One encrypted document for every Bitcoin key you hold. The vault derives and signs so private keys never leave it in the clear; revealing one is a separate, logged operation.

- Holds entropy, mnemonics, extended keys, WIFs, BAP account keys, key shares, and symmetric keys.
- Seals the document under one random key, wrapped by whatever the machine offers: Secure Enclave with Touch ID on macOS, a software device key, a passkey (PRF) in the browser, or a passphrase. Several wraps can coexist, so losing a device does not lose the vault.
- Derives per BRC-157 (entropy to root and profiles), BIP-32, and BRC-42. Roots never sign directly.
- Imports every `bitcoin-backup` payload, plain or encrypted, and exports only encrypted: to a passphrase or sealed to another vault's public key.
- The file is a `bitcoin-backup` v2 envelope, so any reader of that format can inspect its slots without unlocking.

## Install

```bash
bun add @opl.dev/vault
# or run the CLI directly
bunx @opl.dev/vault --help
```

## CLI

Passphrases never go on the command line. Use `--passphrase-file <path>`, `--passphrase-stdin`, or `--passphrase-env <NAME>`.

```bash
vault init --slot passphrase --passphrase-file ~/.vault-pass
vault generate entropy --label main --reason "first key"
vault derive <id> --scheme brc157 --index 1 --label agent
vault pubkey <id>
vault sign <id> deadbeef --protocol "2:my app" --key-id k1
vault shares split <id> -t 2 -n 3
vault export <id> --to-pubkey <65-byte-hex>
vault backup > vault-backup.bep
vault doctor --json
```

Every command takes `--json`, `--vault <path>` (default `~/.bsv/vault.bep`, or `VAULT_PATH`), and `--reason <text>`, which is written to the audit log with each unlock. Exit codes: 0 ok, 1 error, 2 usage, 3 locked, 4 not found, 5 refused by policy.

## Library

```ts
import { createVault, defaultVaultPath, PassphraseProvider, saveVault } from '@opl.dev/vault';

const provider = new PassphraseProvider(process.env.VAULT_PASSPHRASE!);
const vault = await createVault(defaultVaultPath(), [provider]);

const root = vault.generateEntropy('main');
const agent = vault.profile(root.id, 1, 'agent');      // BRC-157 profile, its own identity key

vault.unlock('sign a payment');
const signer = vault.signer(agent.id, { scheme: 'brc42', brc42: { protocolID: [2, 'my app'], keyID: 'k1' } });
const sig = await signer.sign(new TextEncoder().encode('hello'));

await saveVault(defaultVaultPath(), vault, provider);  // keeps every slot
```

`signer()` returns a session-bound object that signs, encrypts, and derives public keys but cannot yield its private key. `reveal(id, reason)` is the only path to plaintext, it always logs, and a vault can be created with it disabled.

Providers: `PassphraseProvider`, `DeviceKeyProvider`, `EnclaveProvider` (macOS), `PrfProvider` (browser). Storage: `FileStorage`, `IndexedDbStorage`, `MemoryStorage`. The browser entry (`@opl.dev/vault/browser`) excludes the enclave and file storage.

## Development

```bash
bun install
bun run check   # lint, test, build
```

The Secure Enclave helper under `swift/` builds on first use on Apple silicon and is skipped elsewhere.

## License

MIT
