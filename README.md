# Evidence Locker

A browser-local evidence catalog for organizing files by case ID, calculating SHA-256 fingerprints, and recording timestamped custody events.

## Run locally

```sh
npm install
npm start
```

Open `http://localhost:3000`. Browser cryptography requires a secure context, which localhost provides.

## Evidence handling

- Files are associated with the case ID entered in the locker and encrypted with AES-GCM using a 256-bit, non-extractable Web Crypto key.
- Encrypted files, metadata, custody events, and the key are stored in this browser's IndexedDB. Evidence is not sent to a server or synchronized between browsers.
- SHA-256 is calculated before encryption and checked again before a file is decrypted for download.
- Custody entries include a timestamp, custodian, action, previous-event hash, and event hash. The interface verifies the event links when a record is selected.
- Extracted metadata includes the file name, media type, size, last-modified time, image/video dimensions, audio/video duration, and PDF version where available.

This is a local catalog, not a tamper-proof or court-certified evidence management system. The encryption key is stored in the same browser profile as the encrypted records, so scripts running on this origin can access the vault. Clearing site data or losing the browser profile can make records unrecoverable. Use a managed server-side evidence system when you need centralized access control, independent key custody, durable backups, or legally auditable records.

## Supabase Phase 1

The optional Supabase Auth panel is enabled when `VITE_SUPABASE_URL` and `VITE_SUPABASE_PUBLISHABLE_KEY` are set. Copy `.env.example` to `.env.local`; the local environment file is gitignored. The publishable key is intended for browser use. Never put a service-role key, secret key, or database password in a `VITE_` variable.

Apply `supabase/migrations/20261030000000_forensiai_team_phase1.sql` to a Supabase project to create team cases, Admin/Investigator/Viewer membership roles, encrypted key envelopes, hash and custody tables, RLS, and a private evidence bucket. The migration adds no evidence rows and does not upload files. Remote evidence upload, local-vault migration, vault-passphrase onboarding, and case-management UI remain disabled for this phase.

The key-sharing primitives in `src/supabase/key-sharing.js` generate a per-member RSA key pair, encrypt the private key under a separate vault passphrase, and wrap a case AES key to each authorized member's public key. Teammates unwrap with their own private key; personal passwords are not shared. The database stores public keys and passphrase-encrypted private-key envelopes, never passphrases or clear private keys.

RLS regression tests are in `supabase/tests/database/rls.test.sql` and are intended to run with Supabase CLI `supabase test db` against a disposable local Supabase stack. Do not apply migrations to production until the migration and policies have been reviewed and tested in a separate project.