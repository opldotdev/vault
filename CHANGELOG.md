# Changelog

## 0.0.2 — 2026-09-09

### Changed
- New passphrase slots are Argon2id (64 MiB, t=3, p=1) instead of PBKDF2. Existing pbkdf2 envelopes still open.
- PassphraseProvider enforces wallet-grade passphrase rules from bitcoin-backup (12+ characters; 16+ or mixed classes). Passphrases are not trimmed.

## 0.0.1 — 2026-09-08

### Added

- Encrypted vault persistence, key entries, derivation, signer handles, and shares.
- Passphrase, device, and browser providers with file and IndexedDB storage.
- Encrypted import and export, including bitcoin-backup compatibility.
- Vault CLI, browser entry point, TypeScript declarations, and usage documentation.
- Automatic package builds and an explicit, typed browser import.
