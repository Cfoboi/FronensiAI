# Evidence Locker

A browser-local evidence catalog for organizing files by case ID, calculating SHA-256 fingerprints, and recording timestamped custody events.

## Run locally

```sh
npm install
npm start
```

Open `http://localhost:3000`. Browser cryptography requires a secure context, which localhost provides.

## Tests

Run the automated tests with `npm test -- --run`. The vault tests use harmless temporary sample data and an in-memory database; they do not access browser IndexedDB or Supabase.

## Evidence handling

- Files are associated with the case ID entered in the locker and encrypted with AES-GCM using a 256-bit, non-extractable Web Crypto key.
- Encrypted files, metadata, custody events, and the key are stored in this browser's IndexedDB. Evidence is not sent to a server or synchronized between browsers.
- SHA-256 is calculated before encryption and checked before a file is decrypted for download. Evidence Details displays the complete hash, supports copying it, and can independently recalculate it from decrypted evidence. File-content verification reports MATCH, MISMATCH, or ERROR with a check time and does not change the stored file, hash, encryption key, or custody history. The separate custody-chain status verifies event links only.
- JPEG and TIFF EXIF metadata is extracted locally when present, including camera details, capture time, orientation, lens, image dimensions, and GPS coordinates. These embedded values can be absent, inaccurate, or altered; they are not independently verified.
- Analysts can record a manual EXIF validation status (VERIFIED, MISMATCH, or NEEDS REVIEW), notes, and artifact references with an evidence record. Validation details are stored in the encrypted metadata and recorded in the custody chain without changing the evidence file or its SHA-256.
- Windows REGF registry hives can be analyzed offline for common startup, typed URL, recent document, UserAssist, USB storage, mounted device, service, user profile, installed application, and Windows version artifacts. Parsing runs locally on a hash-verified copy; saving a report updates only encrypted analysis metadata and the custody chain. A JSON analysis and custody report can be downloaded.
- Classic PCAP and PCAPNG captures can be analyzed locally for packet timestamps, IP endpoints, ports, protocols, bidirectional connection summaries, and possible TCP port-sweep leads. Heuristic indicators are explicitly leads for analyst review, not confirmed threats. PCAP reports and analyst validation are stored as encrypted metadata and custody events, without modifying original evidence bytes or SHA-256.
- SQLite 3 databases can be inspected locally from a SHA-256-verified copy in an in-memory, query-only database. The report lists tables, views, schemas, bounded record samples, and timestamp-like columns with recognized date values. Analyst validation, artifact references, and a custody event are encrypted with metadata; a JSON report can be downloaded without changing original evidence.
- The AI Forensic Copilot uses saved deterministic EXIF, Registry, PCAP, and SQLite outputs plus evidence inventory and custody status. Investigators select evidence, verify its SHA-256, review and individually select the structured facts, and explicitly approve transmission. Original files, encrypted bytes, passphrases, and encryption keys are never sent. AI interpretations and leads are always labeled NEEDS REVIEW; unsupported or uncited claims are excluded and flagged.
- The Investigation Timeline derives events from EXIF dates, timestamp-bearing Registry artifacts, PCAP packets/connections/leads, SQLite timestamp fields, custody events, analyst validations, and saved Copilot findings. It retains each source timestamp, displays timezone/offset information, and converts only explicit-offset timestamps, PCAP UTC timestamps, custody ISO timestamps, and recognized SQLite Unix epochs to UTC. EXIF local times, date-only values, and other ambiguous source values remain in a separate unresolved-time list. Timeline JSON/CSV and the final JSON investigation report are generated as downloads only; they do not write to IndexedDB or alter evidence or custody history. The report includes a fresh SHA-256/custody check, evidence inventory, module findings, AI citations, human validation, timeline, unverified leads, unsupported claims, unresolved questions, and investigator-supplied summary/conclusions.
- Custody entries include a timestamp, custodian, action, previous-event hash, and event hash. The interface verifies the event links when a record is selected.
- Extracted metadata includes the file name, media type, size, last-modified time, image/video dimensions, audio/video duration, and PDF version where available.

This is a local catalog, not a tamper-proof or court-certified evidence management system. The encryption key is stored in the same browser profile as the encrypted records, so scripts running on this origin can access the vault. Clearing site data or losing the browser profile can make records unrecoverable. Use a managed server-side evidence system when you need centralized access control, independent key custody, durable backups, or legally auditable records.

## Supabase Phase 1

The optional Supabase Auth panel is enabled when `VITE_SUPABASE_URL` and `VITE_SUPABASE_PUBLISHABLE_KEY` are set. Copy `.env.example` to `.env.local`; the local environment file is gitignored. The publishable key is intended for browser use. Never put a service-role key, secret key, or database password in a `VITE_` variable.

Apply `supabase/migrations/20261030000000_forensiai_team_phase1.sql` to a Supabase project to create team cases, Admin/Investigator/Viewer membership roles, encrypted key envelopes, hash and custody tables, RLS, and a private evidence bucket. The migration adds no evidence rows and does not upload files. Remote evidence upload, local-vault migration, vault-passphrase onboarding, and case-management UI remain disabled for this phase.

The key-sharing primitives in `src/supabase/key-sharing.js` generate a per-member RSA key pair, encrypt the private key under a separate vault passphrase, and wrap a case AES key to each authorized member's public key. Teammates unwrap with their own private key; personal passwords are not shared. The database stores public keys and passphrase-encrypted private-key envelopes, never passphrases or clear private keys.

### Secure AI Copilot endpoint

`supabase/functions/ai-forensic-copilot/index.ts` is an optional Supabase Edge Function backed by the OpenAI Chat Completions API. The browser sends only investigator-approved structured facts to this endpoint. The function verifies the user JWT, checks active membership for an exact matching Supabase `case_number`, restricts human validation authorization to Admin/Investigator roles, enforces request limits, and keeps the provider key server-side. Evidence text is treated as untrusted data. No original evidence bytes are uploaded, and there is no AI-based primary forensic parsing.

To enable it, deploy the function to an existing Supabase project and configure the function secrets `OPENAI_API_KEY` and `COPILOT_ALLOWED_ORIGINS` (a comma-separated exact origin allowlist, such as `http://localhost:3000` and the production app origin). Optionally set `OPENAI_MODEL`; it defaults to `gpt-4o-mini`. Supabase supplies `SUPABASE_URL`, `SUPABASE_ANON_KEY`, and `SUPABASE_SERVICE_ROLE_KEY` to Edge Functions. Keep all private values in the Supabase server-side function secrets, never in `VITE_` variables. A typical deployment uses `supabase functions deploy ai-forensic-copilot` with an authenticated CLI linked to the intended project; deploying a function does not require a local Docker stack. Deployment credentials and project access are not assumed and no deployment was performed here.

The local evidence case ID must exactly match a `case_number` in the Supabase team schema, and the signed-in user must have active membership in that remote case. The endpoint does not create cases, change database policies, or read/write Supabase evidence. The app displays `AI Copilot unavailable — secure AI provider configuration required.` when the provider is not configured. This repository does not include credentials, so live AI operation has not been tested or enabled.

Saved Copilot findings and human validation history are appended to encrypted local evidence metadata, with a local custody event; original evidence ciphertext and SHA-256 are not changed. Human validation requires a server authorization check and records the investigator identity, notes, independent method, and review time. These findings are not centrally stored or independently signed by the backend, and the browser-local vault is not a tamper-proof audit system. No database migration or Supabase data/policy change is required for this feature.

RLS regression tests are in `supabase/tests/database/rls.test.sql` and are intended to run with Supabase CLI `supabase test db` against a disposable local Supabase stack. Do not apply migrations to production until the migration and policies have been reviewed and tested in a separate project.