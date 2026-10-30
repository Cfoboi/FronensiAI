begin;
select no_plan();

insert into auth.users (
  id, aud, role, email, encrypted_password, email_confirmed_at,
  raw_app_meta_data, raw_user_meta_data, created_at, updated_at
) values
  ('10000000-0000-4000-8000-000000000001', 'authenticated', 'authenticated', 'admin@example.test', '', now(), '{}', '{}', now(), now()),
  ('10000000-0000-4000-8000-000000000002', 'authenticated', 'authenticated', 'investigator@example.test', '', now(), '{}', '{}', now(), now()),
  ('10000000-0000-4000-8000-000000000003', 'authenticated', 'authenticated', 'viewer@example.test', '', now(), '{}', '{}', now(), now()),
  ('10000000-0000-4000-8000-000000000004', 'authenticated', 'authenticated', 'outsider@example.test', '', now(), '{}', '{}', now(), now());

insert into public.cases (id, case_number, created_by) values
  ('20000000-0000-4000-8000-000000000001', 'RLS-TEST-001', '10000000-0000-4000-8000-000000000001'),
  ('20000000-0000-4000-8000-000000000002', 'RLS-TEST-002', '10000000-0000-4000-8000-000000000004');

insert into public.case_memberships (case_id, user_id, role) values
  ('20000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000001', 'admin'),
  ('20000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000002', 'investigator'),
  ('20000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000003', 'viewer'),
  ('20000000-0000-4000-8000-000000000002', '10000000-0000-4000-8000-000000000004', 'admin');

insert into public.evidence_records (
  id, case_id, object_name, encrypted_metadata, upload_status,
  reserved_by, uploaded_at
) values
  ('30000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000001/30000000-0000-4000-8000-000000000001/ciphertext.bin', decode('00', 'hex'), 'uploaded', '10000000-0000-4000-8000-000000000001', now()),
  ('30000000-0000-4000-8000-000000000002', '20000000-0000-4000-8000-000000000002', '20000000-0000-4000-8000-000000000002/30000000-0000-4000-8000-000000000002/ciphertext.bin', decode('00', 'hex'), 'uploaded', '10000000-0000-4000-8000-000000000004', now());

insert into public.evidence_hashes (case_id, evidence_id, algorithm, digest, recorded_by) values
  ('20000000-0000-4000-8000-000000000001', '30000000-0000-4000-8000-000000000001', 'SHA-256', repeat('a', 64), '10000000-0000-4000-8000-000000000001'),
  ('20000000-0000-4000-8000-000000000002', '30000000-0000-4000-8000-000000000002', 'SHA-256', repeat('b', 64), '10000000-0000-4000-8000-000000000004');

insert into public.custody_events (
  case_id, evidence_id, sequence_no, actor_id, action, happened_at,
  previous_hash, event_hash, hash_version
) values
  ('20000000-0000-4000-8000-000000000001', '30000000-0000-4000-8000-000000000001', 1,
   '10000000-0000-4000-8000-000000000001', 'Evidence received', now(), 'GENESIS', repeat('c', 64), 'legacy-v1'),
  ('20000000-0000-4000-8000-000000000002', '30000000-0000-4000-8000-000000000002', 1,
   '10000000-0000-4000-8000-000000000004', 'Evidence received', now(), 'GENESIS', repeat('d', 64), 'legacy-v1');

insert into storage.objects (bucket_id, name) values
  ('forensiai-evidence', '20000000-0000-4000-8000-000000000001/30000000-0000-4000-8000-000000000001/ciphertext.bin'),
  ('forensiai-evidence', '20000000-0000-4000-8000-000000000002/30000000-0000-4000-8000-000000000002/ciphertext.bin');

set local role authenticated;
select set_config('request.jwt.claim.sub', '10000000-0000-4000-8000-000000000001', true);
select is((select count(*)::integer from public.cases), 1, 'Admin sees only member cases');
select is((select count(*)::integer from public.evidence_records), 1, 'Admin sees case evidence');
select is((select count(*)::integer from public.evidence_hashes), 1, 'Admin sees case hashes');
select is((select count(*)::integer from public.custody_events), 1, 'Admin sees custody events');
select ok(public.has_case_role('20000000-0000-4000-8000-000000000001', array['investigator']::public.case_role[]), 'Investigator membership is recognized');
select is((select count(*)::integer from storage.objects where bucket_id = 'forensiai-evidence'), 1, 'Admin reads only member evidence objects');
select throws_ok(
  $$insert into public.evidence_hashes (case_id, evidence_id, algorithm, digest, recorded_by, recorded_at) values ('20000000-0000-4000-8000-000000000001', '30000000-0000-4000-8000-000000000001', 'SHA-256', repeat('e', 64), '10000000-0000-4000-8000-000000000004', now() - interval '1 year')$$,
  '42501', 'Clients cannot directly spoof evidence hash provenance'
);
select set_config('test.submitted_hash_id', public.submit_evidence_hash('30000000-0000-4000-8000-000000000001', repeat('e', 64), now() - interval '1 year')::text, true);
select is((select recorded_by::text from public.evidence_hashes where id = current_setting('test.submitted_hash_id')::uuid), current_setting('request.jwt.claim.sub'), 'Hash submitter is assigned by the server');
select ok((select recorded_at between transaction_timestamp() and clock_timestamp() from public.evidence_hashes where id = current_setting('test.submitted_hash_id')::uuid), 'Hash recorded_at is server assigned');
select is((select verification_status from public.evidence_hashes where id = current_setting('test.submitted_hash_id')::uuid), 'submitted', 'New hash starts as submitted, not verified');
select throws_ok(
  $$update public.evidence_hashes set verification_status = 'independently_verified', verified_by = '10000000-0000-4000-8000-000000000004', verified_at = now() where evidence_id = '30000000-0000-4000-8000-000000000001'$$,
  '42501', 'Clients cannot directly mark a hash independently verified'
);
select throws_ok(
  $$select public.verify_evidence_hash(current_setting('test.submitted_hash_id')::uuid, repeat('e', 64))$$,
  '42501', 'Submitter cannot independently verify their own hash'
);
select throws_ok(
  $$select public.change_case_member_role('20000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000001', 'viewer')$$,
  '23514', 'Case cannot lose its last Admin by role change'
);
select throws_ok(
  $$select public.remove_case_member('20000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000001')$$,
  '23514', 'Case cannot lose its last Admin by removal'
);

reset role;
set local role service_role;
select throws_ok(
  $$delete from auth.users where id = '10000000-0000-4000-8000-000000000001'$$,
  '23503', 'Auth user with case membership cannot be deleted'
);
select throws_ok(
  $$delete from public.cases where id = '20000000-0000-4000-8000-000000000001'$$,
  '55000', 'Case hard delete is rejected'
);
select throws_ok(
  $$delete from public.evidence_records where id = '30000000-0000-4000-8000-000000000001'$$,
  '55000', 'Evidence hard delete is rejected'
);
select throws_ok(
  $$delete from public.evidence_hashes where evidence_id = '30000000-0000-4000-8000-000000000001'$$,
  '55000', 'Evidence hash hard delete is rejected'
);
select throws_ok(
  $$delete from public.custody_events where evidence_id = '30000000-0000-4000-8000-000000000001'$$,
  '55000', 'Custody history hard delete is rejected'
);
select throws_ok(
  $$truncate public.custody_events$$,
  '55000', 'Custody history truncate is rejected'
);
reset role;
set local role authenticated;

select set_config('request.jwt.claim.sub', '10000000-0000-4000-8000-000000000002', true);
select is((select count(*)::integer from public.evidence_records), 1, 'Investigator reads case evidence');
select is((select sequence_no::integer from public.append_custody_event('30000000-0000-4000-8000-000000000001', 'Evidence reviewed', null)), 2, 'Investigator can append a custody event');
select throws_ok(
  $$update public.custody_events set action = 'Edited' where evidence_id = '30000000-0000-4000-8000-000000000001' and sequence_no = 1$$,
  '42501', 'Investigator cannot update custody history'
);
select throws_ok(
  $$delete from public.custody_events where evidence_id = '30000000-0000-4000-8000-000000000001' and sequence_no = 1$$,
  '42501', 'Investigator cannot delete custody history'
);
select is((select count(*)::integer from storage.objects where bucket_id = 'forensiai-evidence'), 1, 'Investigator reads only member evidence objects');
select throws_ok(
  $$insert into storage.objects (bucket_id, name) values ('forensiai-evidence', '20000000-0000-4000-8000-000000000001/40000000-0000-4000-8000-000000000001/ciphertext.bin')$$,
  '42501', 'Investigator cannot upload an unreserved object path'
);
select throws_ok(
  $$select public.verify_evidence_hash(current_setting('test.submitted_hash_id')::uuid, repeat('f', 64))$$,
  '23514', 'Independent digest must match the submitted digest'
);
select lives_ok(
  $$select public.verify_evidence_hash(current_setting('test.submitted_hash_id')::uuid, repeat('e', 64))$$,
  'A different Investigator can independently verify a matching digest'
);
select is((select verification_status from public.evidence_hashes where id = current_setting('test.submitted_hash_id')::uuid), 'independently_verified', 'Matching independent digest advances verification state');
select is((select verified_by::text from public.evidence_hashes where id = current_setting('test.submitted_hash_id')::uuid), current_setting('request.jwt.claim.sub'), 'Verifier is assigned by the server');
select ok((select verified_at between transaction_timestamp() and clock_timestamp() from public.evidence_hashes where id = current_setting('test.submitted_hash_id')::uuid), 'Verification timestamp is server assigned');
select set_config(
  'test.reserved_evidence_id',
  (select evidence_id::text from public.reserve_evidence_upload('20000000-0000-4000-8000-000000000001', decode('01', 'hex'), repeat('f', 64), now())),
  true
);
select set_config(
  'test.reserved_object_name',
  (select object_name from public.evidence_records where id = current_setting('test.reserved_evidence_id')::uuid),
  true
);
select is((select upload_status from public.evidence_records where id = current_setting('test.reserved_evidence_id')::uuid), 'reserved', 'Reservation creates a matching pending evidence row');
select ok(public.can_upload_storage_object(current_setting('test.reserved_object_name')), 'Only the reserving Investigator can upload the reserved path');
select ok(not public.can_upload_storage_object('20000000-0000-4000-8000-000000000001/40000000-0000-4000-8000-000000000001/ciphertext.bin'), 'Reservation cannot authorize a different evidence ID');
select set_config('request.jwt.claim.sub', '10000000-0000-4000-8000-000000000003', true);
select throws_ok(
  $$select public.reserve_evidence_upload('20000000-0000-4000-8000-000000000001', decode('01', 'hex'), repeat('f', 64), now())$$,
  '42501', 'Viewer cannot reserve an evidence upload'
);
select is((select count(*)::integer from public.evidence_records), 1, 'Viewer cannot see an uncompleted reservation');
select ok(not public.can_upload_storage_object(current_setting('test.reserved_object_name')), 'Viewer cannot use another member''s reservation');
select throws_ok(
  format('insert into storage.objects (bucket_id, name) values (%L, %L)', 'forensiai-evidence', current_setting('test.reserved_object_name')),
  '42501', 'Viewer cannot upload a reserved evidence object'
);
select set_config('request.jwt.claim.sub', '10000000-0000-4000-8000-000000000002', true);
select lives_ok(
  format('insert into storage.objects (bucket_id, name) values (%L, %L)', 'forensiai-evidence', current_setting('test.reserved_object_name')),
  'Reserved evidence object can be uploaded'
);
select lives_ok(
  format('select public.complete_evidence_upload(%L::uuid)', current_setting('test.reserved_evidence_id')),
  'Reservation can be finalized after object upload'
);
select is((select upload_status from public.evidence_records where id = current_setting('test.reserved_evidence_id')::uuid), 'uploaded', 'Finalized evidence is marked uploaded');
select is((select count(*)::integer from storage.objects where bucket_id = 'forensiai-evidence'), 2, 'Investigator can see both uploaded member objects');

select set_config('request.jwt.claim.sub', '10000000-0000-4000-8000-000000000003', true);
select is((select count(*)::integer from public.cases), 1, 'Viewer can read their case');
select is((select count(*)::integer from public.evidence_records), 2, 'Viewer can read completed evidence metadata');
select is((select count(*)::integer from public.evidence_hashes), 3, 'Viewer can read submitted and verified hash records');
select is((select count(*)::integer from public.custody_events), 2, 'Viewer can read custody history');
select is((select count(*)::integer from storage.objects where bucket_id = 'forensiai-evidence'), 2, 'Viewer can read member evidence objects');
select ok(public.has_storage_case_role('20000000-0000-4000-8000-000000000001/30000000-0000-4000-8000-000000000001/ciphertext.bin', array['admin', 'investigator', 'viewer']::public.case_role[]), 'Viewer can read member evidence objects');
select ok(not public.has_storage_case_role('20000000-0000-4000-8000-000000000001/30000000-0000-4000-8000-000000000001/ciphertext.bin', array['admin', 'investigator']::public.case_role[]), 'Viewer cannot upload evidence objects');
select throws_ok(
  $$insert into public.evidence_hashes (case_id, evidence_id, algorithm, digest) values ('20000000-0000-4000-8000-000000000001', '30000000-0000-4000-8000-000000000001', 'SHA-256', repeat('e', 64))$$,
  '42501', 'Viewer cannot add evidence hashes'
);
select throws_ok(
  $$insert into storage.objects (bucket_id, name) values ('forensiai-evidence', '20000000-0000-4000-8000-000000000001/40000000-0000-4000-8000-000000000001/ciphertext.bin')$$,
  '42501', 'Viewer cannot upload evidence objects'
);
select throws_ok(
  $$select public.append_custody_event('30000000-0000-4000-8000-000000000001', 'Evidence reviewed', null)$$,
  '42501', 'Only case Admins and Investigators can append custody events',
  'Viewer cannot append custody events'
);

select set_config('request.jwt.claim.sub', '10000000-0000-4000-8000-000000000004', true);
select is((select count(*)::integer from public.cases), 1, 'Non-member cannot see another case');
select is((select count(*)::integer from storage.objects where bucket_id = 'forensiai-evidence'), 1, 'Non-member reads only their own case objects');
select ok(not public.has_storage_case_role('20000000-0000-4000-8000-000000000001/30000000-0000-4000-8000-000000000001/ciphertext.bin', array['admin', 'investigator', 'viewer']::public.case_role[]), 'Non-member cannot read case storage');

select set_config('request.jwt.claim.sub', '10000000-0000-4000-8000-000000000001', true);
select lives_ok(
  $$select public.resolve_case_member_offboarding('20000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000002')$$,
  'Admin can explicitly resolve a non-Admin member before account deletion'
);
select is((select count(*)::integer from public.case_memberships where user_id = '10000000-0000-4000-8000-000000000002'), 0, 'Offboarding resolves all case membership rows');
reset role;
set local role service_role;
select lives_ok(
  $$delete from auth.users where id = '10000000-0000-4000-8000-000000000002'$$,
  'Auth account can be deleted after all memberships are explicitly resolved'
);
reset role;
set local role authenticated;
select set_config('request.jwt.claim.sub', '10000000-0000-4000-8000-000000000001', true);
select lives_ok(
  $$select public.archive_evidence_record('30000000-0000-4000-8000-000000000001')$$,
  'Evidence can be archived without deleting its records'
);
select is((select count(*)::integer from public.evidence_records where id = '30000000-0000-4000-8000-000000000001'), 1, 'Archived evidence record remains stored');
select is((select count(*)::integer from public.custody_events where evidence_id = '30000000-0000-4000-8000-000000000001'), 3, 'Archiving evidence preserves and appends custody history');
select lives_ok(
  $$select public.archive_case('20000000-0000-4000-8000-000000000001')$$,
  'Case can be archived after pending uploads are resolved'
);
select ok((select archived_at is not null and archived_by = '10000000-0000-4000-8000-000000000001' from public.cases where id = '20000000-0000-4000-8000-000000000001'), 'Case archive records actor and timestamp');
select is((select count(*)::integer from public.evidence_hashes where evidence_id = '30000000-0000-4000-8000-000000000001'), 2, 'Archiving a case preserves evidence hash history');

reset role;
set local role anon;
select ok(not public.has_storage_case_role('20000000-0000-4000-8000-000000000001/30000000-0000-4000-8000-000000000001/ciphertext.bin', array['admin', 'investigator', 'viewer']::public.case_role[]), 'Anonymous Storage read helper fails closed');
select ok(not public.can_upload_storage_object('20000000-0000-4000-8000-000000000001/40000000-0000-4000-8000-000000000001/ciphertext.bin'), 'Anonymous Storage upload helper fails closed');
select throws_ok(
  $$insert into storage.objects (bucket_id, name) values ('forensiai-evidence', '20000000-0000-4000-8000-000000000001/40000000-0000-4000-8000-000000000001/ciphertext.bin')$$,
  '42501', 'Anonymous upload is denied without helper permission errors'
);

reset role;
select * from finish();
rollback;