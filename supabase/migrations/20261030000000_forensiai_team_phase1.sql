begin;

create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;

do $$ begin
  create type public.case_role as enum ('admin', 'investigator', 'viewer');
exception when duplicate_object then null;
end $$;

create table if not exists public.cases (
  id uuid primary key default gen_random_uuid(),
  case_number text not null unique check (length(btrim(case_number)) between 1 and 120),
  encrypted_title bytea,
  created_by uuid,
  created_at timestamptz not null default clock_timestamp(),
  archived_at timestamptz,
  archived_by uuid,
  key_version integer not null default 1 check (key_version > 0)
);

create table if not exists public.case_memberships (
  case_id uuid not null references public.cases(id) on delete restrict,
  user_id uuid not null references auth.users(id) on delete restrict,
  role public.case_role not null,
  is_active boolean not null default true,
  invited_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default clock_timestamp(),
  primary key (case_id, user_id)
);

create index if not exists case_memberships_user_active_idx
  on public.case_memberships (user_id, case_id) where is_active;

create table if not exists public.member_public_keys (
  user_id uuid primary key references auth.users(id) on delete cascade,
  algorithm text not null check (algorithm = 'RSA-OAEP-3072-SHA256'),
  format_version smallint not null check (format_version = 1),
  public_jwk jsonb not null,
  fingerprint text not null check (fingerprint ~ '^[0-9a-f]{64}$'),
  created_at timestamptz not null default clock_timestamp(),
  updated_at timestamptz not null default clock_timestamp(),
  constraint member_public_jwk_has_no_private_material
    check (not (public_jwk ?| array['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth']))
);

create table if not exists public.member_key_vaults (
  user_id uuid primary key references auth.users(id) on delete cascade,
  format_version smallint not null check (format_version = 1),
  kdf text not null check (kdf = 'PBKDF2-SHA256'),
  kdf_iterations integer not null check (kdf_iterations >= 600000),
  cipher text not null check (cipher = 'AES-256-GCM'),
  salt text not null,
  iv text not null,
  encrypted_private_key text not null,
  updated_at timestamptz not null default clock_timestamp()
);

create table if not exists public.case_key_envelopes (
  case_id uuid not null references public.cases(id) on delete restrict,
  user_id uuid not null references auth.users(id) on delete cascade,
  key_version integer not null check (key_version > 0),
  format_version smallint not null check (format_version = 1),
  algorithm text not null check (algorithm = 'RSA-OAEP-3072-SHA256'),
  encrypted_case_key text not null,
  created_by uuid,
  created_at timestamptz not null default clock_timestamp(),
  primary key (case_id, user_id, key_version)
);

create table if not exists public.evidence_records (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null references public.cases(id) on delete restrict,
  object_name text not null unique,
  encrypted_metadata bytea not null,
  upload_status text not null default 'reserved' check (upload_status in ('reserved', 'uploaded')),
  reserved_by uuid references auth.users(id) on delete set null,
  reservation_expires_at timestamptz not null default (clock_timestamp() + interval '30 minutes'),
  uploaded_at timestamptz,
  original_created_at timestamptz,
  added_by uuid,
  added_at timestamptz not null default clock_timestamp(),
  archived_at timestamptz,
  archived_by uuid,
  check ((upload_status = 'reserved' and uploaded_at is null and reserved_by is not null) or (upload_status = 'uploaded' and uploaded_at is not null)),
  unique (id, case_id)
);

create index if not exists evidence_records_case_added_idx
  on public.evidence_records (case_id, added_at desc);

create table if not exists public.evidence_hashes (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null,
  evidence_id uuid not null,
  algorithm text not null check (algorithm = 'SHA-256'),
  digest text not null check (digest ~ '^[0-9a-f]{64}$'),
  verification_status text not null default 'submitted'
    check (verification_status in ('submitted', 'independently_verified')),
  source_timestamp timestamptz,
  recorded_by uuid,
  recorded_at timestamptz not null default clock_timestamp(),
  verified_by uuid,
  verified_at timestamptz,
  check (
    (verification_status = 'submitted' and verified_by is null and verified_at is null)
    or (verification_status = 'independently_verified' and verified_by is not null and verified_at is not null)
  ),
  foreign key (evidence_id, case_id) references public.evidence_records(id, case_id) on delete restrict
);

create index if not exists evidence_hashes_case_idx
  on public.evidence_hashes (case_id, evidence_id, recorded_at);

create table if not exists public.custody_events (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null,
  evidence_id uuid not null,
  sequence_no bigint not null check (sequence_no > 0),
  actor_id uuid,
  actor_label_ciphertext bytea,
  action text not null check (length(btrim(action)) between 1 and 160),
  details_ciphertext bytea,
  happened_at timestamptz not null,
  recorded_at timestamptz not null default clock_timestamp(),
  previous_hash text not null,
  event_hash text not null check (event_hash ~ '^[0-9a-f]{64}$'),
  hash_version text not null check (hash_version in ('legacy-v1', 'forensiai-custody-v1')),
  unique (evidence_id, sequence_no),
  foreign key (evidence_id, case_id) references public.evidence_records(id, case_id) on delete restrict
);

create index if not exists custody_events_case_order_idx
  on public.custody_events (case_id, evidence_id, sequence_no);

create table if not exists public.case_audit_events (
  id uuid primary key default gen_random_uuid(),
  case_id uuid not null references public.cases(id) on delete restrict,
  evidence_id uuid,
  actor_id uuid,
  target_user_id uuid,
  event_type text not null check (event_type in ('case_created', 'case_archived', 'evidence_archived', 'member_added', 'member_role_changed', 'member_removed')),
  created_at timestamptz not null default clock_timestamp(),
  foreign key (evidence_id, case_id) references public.evidence_records(id, case_id) on delete restrict
);

create index if not exists case_audit_events_case_created_idx
  on public.case_audit_events (case_id, created_at desc);

create or replace function public.prevent_forensic_delete()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  raise exception using
    errcode = '55000',
    message = format('%s records are immutable; archive records instead.', tg_table_name);
end;
$$;

create trigger cases_no_hard_delete
  before delete on public.cases
  for each row execute function public.prevent_forensic_delete();
create trigger cases_no_truncate
  before truncate on public.cases
  for each statement execute function public.prevent_forensic_delete();
create trigger evidence_records_no_hard_delete
  before delete on public.evidence_records
  for each row execute function public.prevent_forensic_delete();
create trigger evidence_records_no_truncate
  before truncate on public.evidence_records
  for each statement execute function public.prevent_forensic_delete();
create trigger evidence_hashes_no_hard_delete
  before delete on public.evidence_hashes
  for each row execute function public.prevent_forensic_delete();
create trigger evidence_hashes_no_truncate
  before truncate on public.evidence_hashes
  for each statement execute function public.prevent_forensic_delete();
create trigger custody_events_no_hard_delete
  before delete on public.custody_events
  for each row execute function public.prevent_forensic_delete();
create trigger custody_events_no_truncate
  before truncate on public.custody_events
  for each statement execute function public.prevent_forensic_delete();
create trigger case_audit_events_no_hard_delete
  before delete on public.case_audit_events
  for each row execute function public.prevent_forensic_delete();
create trigger case_audit_events_no_truncate
  before truncate on public.case_audit_events
  for each statement execute function public.prevent_forensic_delete();

create or replace function public.has_case_role(p_case_id uuid, p_roles public.case_role[])
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.case_memberships membership
    where membership.case_id = p_case_id
      and membership.user_id = auth.uid()
      and membership.is_active
      and membership.role = any (p_roles)
  );
$$;

create or replace function public.archive_case(p_case_id uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_archived_at timestamptz;
begin
  select archived_at into v_archived_at
  from public.cases
  where id = p_case_id
  for update;
  if not found then
    raise exception using errcode = 'P0002', message = 'Case not found.';
  end if;
  if not public.has_case_role(p_case_id, array['admin']::public.case_role[]) then
    raise exception using errcode = '42501', message = 'Only case Admins can archive a case.';
  end if;
  if v_archived_at is not null then
    return;
  end if;
  if exists (
    select 1 from public.evidence_records
    where case_id = p_case_id and upload_status = 'reserved'
  ) then
    raise exception using errcode = '55000', message = 'Resolve pending evidence reservations before archiving the case.';
  end if;

  update public.cases
  set archived_at = clock_timestamp(), archived_by = auth.uid()
  where id = p_case_id;
  insert into public.case_audit_events (case_id, actor_id, event_type)
  values (p_case_id, auth.uid(), 'case_archived');
end;
$$;

create or replace function public.archive_evidence_record(p_evidence_id uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_case_id uuid;
  v_archived_at timestamptz;
  v_upload_status text;
begin
  select case_id into v_case_id from public.evidence_records where id = p_evidence_id;
  if v_case_id is null then
    raise exception using errcode = 'P0002', message = 'Evidence record not found.';
  end if;
  perform 1 from public.cases where id = v_case_id for update;
  select archived_at, upload_status
  into v_archived_at, v_upload_status
  from public.evidence_records
  where id = p_evidence_id
  for update;
  if not public.has_case_role(v_case_id, array['admin', 'investigator']::public.case_role[])
    or exists (select 1 from public.cases where id = v_case_id and archived_at is not null) then
    raise exception using errcode = '42501', message = 'Evidence can only be archived by a case Admin or Investigator in an active case.';
  end if;
  if v_upload_status <> 'uploaded' then
    raise exception using errcode = '55000', message = 'Complete the evidence upload before archiving it.';
  end if;
  if v_archived_at is not null then
    return;
  end if;

  perform public.append_custody_event(p_evidence_id, 'Evidence archived', null);
  update public.evidence_records
  set archived_at = clock_timestamp(), archived_by = auth.uid()
  where id = p_evidence_id;
  insert into public.case_audit_events (case_id, evidence_id, actor_id, event_type)
  values (v_case_id, p_evidence_id, auth.uid(), 'evidence_archived');
end;
$$;

create or replace function public.resolve_case_member_offboarding(p_case_id uuid, p_user_id uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_actor uuid := auth.uid();
  v_role public.case_role;
begin
  perform 1 from public.cases where id = p_case_id for update;
  if not found then
    raise exception using errcode = 'P0002', message = 'Case not found.';
  end if;
  if not public.has_case_role(p_case_id, array['admin']::public.case_role[]) then
    raise exception using errcode = '42501', message = 'Only case Admins can resolve member offboarding.';
  end if;
  select role into v_role
  from public.case_memberships
  where case_id = p_case_id and user_id = p_user_id
  for update;
  if v_role is null then
    raise exception using errcode = 'P0002', message = 'Case membership not found.';
  end if;
  if v_role = 'admin'
    and (select count(*) from public.case_memberships where case_id = p_case_id and is_active and role = 'admin') <= 1 then
    raise exception using errcode = '23514', message = 'Transfer Admin role before offboarding the last Admin.';
  end if;

  delete from public.case_key_envelopes where case_id = p_case_id and user_id = p_user_id;
  delete from public.case_memberships where case_id = p_case_id and user_id = p_user_id;
  insert into public.case_audit_events (case_id, actor_id, target_user_id, event_type)
  values (p_case_id, v_actor, p_user_id, 'member_removed');
end;
$$;

create or replace function public.has_storage_case_role(p_object_name text, p_roles public.case_role[])
returns boolean
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_case_id uuid;
begin
  if p_object_name !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/ciphertext\.bin$' then
    return false;
  end if;
  v_case_id := split_part(p_object_name, '/', 1)::uuid;
  return exists (
    select 1
    from public.evidence_records evidence
    where evidence.case_id = v_case_id
      and evidence.object_name = p_object_name
      and evidence.upload_status = 'uploaded'
      and public.has_case_role(evidence.case_id, p_roles)
  );
end;
$$;

create or replace function public.can_upload_storage_object(p_object_name text)
returns boolean
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_case_id uuid;
begin
  if p_object_name !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/ciphertext\.bin$' then
    return false;
  end if;
  v_case_id := split_part(p_object_name, '/', 1)::uuid;
  return exists (
    select 1
    from public.evidence_records evidence
    where evidence.case_id = v_case_id
      and evidence.object_name = p_object_name
      and evidence.upload_status = 'reserved'
      and evidence.reserved_by = auth.uid()
      and evidence.reservation_expires_at > clock_timestamp()
      and evidence.archived_at is null
      and exists (
        select 1 from public.cases case_row
        where case_row.id = evidence.case_id and case_row.archived_at is null
      )
      and public.has_case_role(evidence.case_id, array['admin', 'investigator']::public.case_role[])
  );
end;
$$;

create or replace function public.submit_evidence_hash(
  p_evidence_id uuid,
  p_digest text,
  p_source_timestamp timestamptz default null
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_case_id uuid;
  v_hash_id uuid;
  v_actor uuid := auth.uid();
begin
  if v_actor is null then
    raise exception using errcode = '42501', message = 'Authentication required.';
  end if;
  if p_digest is null or p_digest !~ '^[0-9a-f]{64}$' then
    raise exception using errcode = '22023', message = 'Invalid SHA-256 digest.';
  end if;
  select evidence.case_id into v_case_id
  from public.evidence_records evidence
  join public.cases case_row on case_row.id = evidence.case_id
  where evidence.id = p_evidence_id
    and evidence.archived_at is null
    and case_row.archived_at is null;
  if v_case_id is null then
    raise exception using errcode = 'P0002', message = 'Evidence record not found.';
  end if;
  if not public.has_case_role(v_case_id, array['admin', 'investigator']::public.case_role[]) then
    raise exception using errcode = '42501', message = 'Only case Admins and Investigators can submit evidence hashes.';
  end if;

  insert into public.evidence_hashes (
    case_id, evidence_id, algorithm, digest, verification_status,
    source_timestamp, recorded_by, recorded_at
  ) values (
    v_case_id, p_evidence_id, 'SHA-256', p_digest, 'submitted',
    p_source_timestamp, v_actor, clock_timestamp()
  ) returning id into v_hash_id;
  return v_hash_id;
end;
$$;

create or replace function public.reserve_evidence_upload(
  p_case_id uuid,
  p_encrypted_metadata bytea,
  p_sha256 text,
  p_original_created_at timestamptz default null
)
returns table (evidence_id uuid, object_name text, reservation_expires_at timestamptz)
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_evidence_id uuid := gen_random_uuid();
  v_object_name text;
  v_expires_at timestamptz := clock_timestamp() + interval '30 minutes';
  v_actor uuid := auth.uid();
begin
  perform 1 from public.cases where id = p_case_id and archived_at is null for update;
  if not found then
    raise exception using errcode = '55000', message = 'Case not found or archived.';
  end if;
  if not public.has_case_role(p_case_id, array['admin', 'investigator']::public.case_role[]) then
    raise exception using errcode = '42501', message = 'Only case Admins and Investigators can reserve evidence uploads.';
  end if;
  if p_encrypted_metadata is null or p_sha256 is null or p_sha256 !~ '^[0-9a-f]{64}$' then
    raise exception using errcode = '22023', message = 'Encrypted metadata and a valid SHA-256 digest are required.';
  end if;

  v_object_name := p_case_id::text || '/' || v_evidence_id::text || '/ciphertext.bin';
  insert into public.evidence_records (
    id, case_id, object_name, encrypted_metadata, upload_status, reserved_by,
    reservation_expires_at, original_created_at, added_by
  ) values (
    v_evidence_id, p_case_id, v_object_name, p_encrypted_metadata, 'reserved',
    v_actor, v_expires_at, p_original_created_at, v_actor
  );
  perform public.submit_evidence_hash(v_evidence_id, p_sha256, p_original_created_at);

  return query select v_evidence_id, v_object_name, v_expires_at;
end;
$$;

create or replace function public.complete_evidence_upload(p_evidence_id uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_evidence public.evidence_records;
  v_case_id uuid;
begin
  select case_id into v_case_id from public.evidence_records where id = p_evidence_id;
  if v_case_id is null then
    raise exception using errcode = 'P0002', message = 'Evidence reservation not found.';
  end if;
  perform 1 from public.cases where id = v_case_id and archived_at is null for update;
  if not found then
    raise exception using errcode = '55000', message = 'Case not found or archived.';
  end if;
  select * into v_evidence
  from public.evidence_records
  where id = p_evidence_id
  for update;
  if not found then
    raise exception using errcode = 'P0002', message = 'Evidence reservation not found.';
  end if;
  if v_evidence.upload_status <> 'reserved'
    or v_evidence.reserved_by <> auth.uid()
    or v_evidence.archived_at is not null
    or v_evidence.reservation_expires_at <= clock_timestamp()
    or not public.has_case_role(v_evidence.case_id, array['admin', 'investigator']::public.case_role[]) then
    raise exception using errcode = '42501', message = 'Evidence reservation is not active for this investigator.';
  end if;
  if not exists (
    select 1 from storage.objects stored_object
    where stored_object.bucket_id = 'forensiai-evidence'
      and stored_object.name = v_evidence.object_name
  ) then
    raise exception using errcode = 'P0002', message = 'Reserved evidence object has not been uploaded.';
  end if;

  update public.evidence_records
  set upload_status = 'uploaded', uploaded_at = clock_timestamp(), reserved_by = null
  where id = p_evidence_id;
end;
$$;

create or replace function public.create_case(
  p_case_number text,
  p_encrypted_title bytea,
  p_owner_key_envelope jsonb
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user_id uuid := auth.uid();
  v_case_id uuid;
begin
  if v_user_id is null then
    raise exception using errcode = '42501', message = 'Authentication required.';
  end if;
  if p_case_number is null or length(btrim(p_case_number)) not between 1 and 120 then
    raise exception using errcode = '22023', message = 'Invalid case number.';
  end if;
  if p_owner_key_envelope->>'algorithm' <> 'RSA-OAEP-3072-SHA256'
    or (p_owner_key_envelope->>'formatVersion')::integer <> 1 then
    raise exception using errcode = '22023', message = 'Invalid owner key envelope.';
  end if;

  insert into public.cases (case_number, encrypted_title, created_by)
  values (btrim(p_case_number), p_encrypted_title, v_user_id)
  returning id into v_case_id;

  insert into public.case_memberships (case_id, user_id, role, invited_by)
  values (v_case_id, v_user_id, 'admin', v_user_id);

  insert into public.case_key_envelopes
    (case_id, user_id, key_version, format_version, algorithm, encrypted_case_key, created_by)
  values (
    v_case_id, v_user_id, 1, 1, 'RSA-OAEP-3072-SHA256',
    p_owner_key_envelope->>'ciphertext', v_user_id
  );

  insert into public.case_audit_events (case_id, actor_id, target_user_id, event_type)
  values (v_case_id, v_user_id, v_user_id, 'case_created');

  return v_case_id;
end;
$$;

create or replace function public.add_case_member(
  p_case_id uuid,
  p_user_id uuid,
  p_role public.case_role,
  p_key_envelope jsonb
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_actor uuid := auth.uid();
  v_key_version integer;
begin
  perform 1 from public.cases where id = p_case_id and archived_at is null for update;
  if not found then
    raise exception using errcode = '55000', message = 'Case not found or archived.';
  end if;
  if not public.has_case_role(p_case_id, array['admin']::public.case_role[]) then
    raise exception using errcode = '42501', message = 'Only case Admins can add members.';
  end if;
  if p_key_envelope->>'algorithm' <> 'RSA-OAEP-3072-SHA256'
    or (p_key_envelope->>'formatVersion')::integer <> 1
    or not exists (select 1 from public.member_public_keys where user_id = p_user_id) then
    raise exception using errcode = '22023', message = 'A valid recipient key envelope is required.';
  end if;
  select key_version into v_key_version from public.cases where id = p_case_id;

  insert into public.case_memberships (case_id, user_id, role, is_active, invited_by)
  values (p_case_id, p_user_id, p_role, true, v_actor)
  on conflict (case_id, user_id) do update
    set role = excluded.role, is_active = true, invited_by = excluded.invited_by;

  insert into public.case_key_envelopes
    (case_id, user_id, key_version, format_version, algorithm, encrypted_case_key, created_by)
  values (
    p_case_id, p_user_id, v_key_version, 1, 'RSA-OAEP-3072-SHA256',
    p_key_envelope->>'ciphertext', v_actor
  )
  on conflict (case_id, user_id, key_version) do update
    set encrypted_case_key = excluded.encrypted_case_key,
        created_by = excluded.created_by,
        created_at = clock_timestamp();

  insert into public.case_audit_events (case_id, actor_id, target_user_id, event_type)
  values (p_case_id, v_actor, p_user_id, 'member_added');
end;
$$;

create or replace function public.change_case_member_role(
  p_case_id uuid,
  p_user_id uuid,
  p_role public.case_role
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_actor uuid := auth.uid();
  v_old_role public.case_role;
begin
  perform 1 from public.cases where id = p_case_id for update;
  if not found then
    raise exception using errcode = 'P0002', message = 'Case not found.';
  end if;
  if not public.has_case_role(p_case_id, array['admin']::public.case_role[]) then
    raise exception using errcode = '42501', message = 'Only case Admins can change member roles.';
  end if;
  select role into v_old_role
  from public.case_memberships
  where case_id = p_case_id and user_id = p_user_id and is_active
  for update;
  if v_old_role is null then
    raise exception using errcode = 'P0002', message = 'Active case member not found.';
  end if;
  if v_old_role = 'admin' and p_role <> 'admin'
    and (select count(*) from public.case_memberships where case_id = p_case_id and is_active and role = 'admin') <= 1 then
    raise exception using errcode = '23514', message = 'A case must retain at least one Admin.';
  end if;
  update public.case_memberships set role = p_role where case_id = p_case_id and user_id = p_user_id;
  insert into public.case_audit_events (case_id, actor_id, target_user_id, event_type)
  values (p_case_id, v_actor, p_user_id, 'member_role_changed');
end;
$$;

create or replace function public.remove_case_member(p_case_id uuid, p_user_id uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_actor uuid := auth.uid();
  v_old_role public.case_role;
begin
  perform 1 from public.cases where id = p_case_id for update;
  if not found then
    raise exception using errcode = 'P0002', message = 'Case not found.';
  end if;
  if not public.has_case_role(p_case_id, array['admin']::public.case_role[]) then
    raise exception using errcode = '42501', message = 'Only case Admins can remove members.';
  end if;
  select role into v_old_role
  from public.case_memberships
  where case_id = p_case_id and user_id = p_user_id and is_active
  for update;
  if v_old_role is null then
    raise exception using errcode = 'P0002', message = 'Active case member not found.';
  end if;
  if v_old_role = 'admin'
    and (select count(*) from public.case_memberships where case_id = p_case_id and is_active and role = 'admin') <= 1 then
    raise exception using errcode = '23514', message = 'A case must retain at least one Admin.';
  end if;
  update public.case_memberships set is_active = false where case_id = p_case_id and user_id = p_user_id;
  delete from public.case_key_envelopes where case_id = p_case_id and user_id = p_user_id;
  insert into public.case_audit_events (case_id, actor_id, target_user_id, event_type)
  values (p_case_id, v_actor, p_user_id, 'member_removed');
end;
$$;

create or replace function public.verify_evidence_hash(
  p_hash_id uuid,
  p_independent_digest text
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_case_id uuid;
  v_digest text;
  v_submitter uuid;
  v_status text;
  v_upload_status text;
begin
  if auth.uid() is null then
    raise exception using errcode = '42501', message = 'Authentication required.';
  end if;
  select case_id, digest, recorded_by, verification_status
  into v_case_id, v_digest, v_submitter, v_status
  from public.evidence_hashes
  where id = p_hash_id
  for update;
  if v_case_id is null then
    raise exception using errcode = 'P0002', message = 'Evidence hash not found.';
  end if;
  if not public.has_case_role(v_case_id, array['admin', 'investigator']::public.case_role[]) then
    raise exception using errcode = '42501', message = 'Only case Admins and Investigators can verify evidence hashes.';
  end if;
  if v_status <> 'submitted' or v_submitter = auth.uid() then
    raise exception using errcode = '42501', message = 'A different investigator must verify a submitted hash.';
  end if;
  select upload_status into v_upload_status
  from public.evidence_records
  where id = (select evidence_id from public.evidence_hashes where id = p_hash_id);
  if v_upload_status <> 'uploaded' then
    raise exception using errcode = '55000', message = 'Evidence must be uploaded before its hash can be independently verified.';
  end if;
  if p_independent_digest is null or p_independent_digest !~ '^[0-9a-f]{64}$'
    or p_independent_digest <> v_digest then
    raise exception using errcode = '23514', message = 'Independent digest does not match the submitted digest.';
  end if;
  update public.evidence_hashes
  set verification_status = 'independently_verified',
      verified_by = auth.uid(),
      verified_at = clock_timestamp()
  where id = p_hash_id;
end;
$$;

create or replace function public.append_custody_event(
  p_evidence_id uuid,
  p_action text,
  p_details_ciphertext bytea default null
)
returns public.custody_events
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_event public.custody_events;
  v_case_id uuid;
  v_sequence bigint;
  v_previous_hash text;
  v_happened_at timestamptz;
  v_hash_input text;
begin
  select case_id into v_case_id
  from public.evidence_records
  where id = p_evidence_id and archived_at is null;
  if v_case_id is null then
    raise exception using errcode = '55000', message = 'Evidence record not found or archived.';
  end if;
  perform 1 from public.cases where id = v_case_id and archived_at is null for update;
  if not found then
    raise exception using errcode = '55000', message = 'Case not found or archived.';
  end if;
  perform 1 from public.evidence_records where id = p_evidence_id for update;
  if not found then
    raise exception using errcode = 'P0002', message = 'Evidence record not found.';
  end if;
  if not public.has_case_role(v_case_id, array['admin', 'investigator']::public.case_role[]) then
    raise exception using errcode = '42501', message = 'Only case Admins and Investigators can append custody events.';
  end if;
  if p_action is null or length(btrim(p_action)) not between 1 and 160 then
    raise exception using errcode = '22023', message = 'Invalid custody action.';
  end if;

  select coalesce(max(sequence_no), 0) + 1, coalesce((array_agg(event_hash order by sequence_no desc))[1], 'GENESIS')
  into v_sequence, v_previous_hash
  from public.custody_events
  where evidence_id = p_evidence_id;
  v_happened_at := clock_timestamp();
  v_hash_input := concat_ws('|',
    'forensiai-custody-v1', p_evidence_id::text, v_sequence::text, auth.uid()::text,
    to_char(v_happened_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    btrim(p_action), v_previous_hash
  );

  insert into public.custody_events (
    case_id, evidence_id, sequence_no, actor_id, action, details_ciphertext,
    happened_at, previous_hash, event_hash, hash_version
  ) values (
    v_case_id, p_evidence_id, v_sequence, auth.uid(), btrim(p_action), p_details_ciphertext,
    v_happened_at, v_previous_hash,
    encode(extensions.digest(convert_to(v_hash_input, 'UTF8'), 'sha256'), 'hex'),
    'forensiai-custody-v1'
  ) returning * into v_event;
  return v_event;
end;
$$;

alter table public.cases enable row level security;
alter table public.case_memberships enable row level security;
alter table public.member_public_keys enable row level security;
alter table public.member_key_vaults enable row level security;
alter table public.case_key_envelopes enable row level security;
alter table public.evidence_records enable row level security;
alter table public.evidence_hashes enable row level security;
alter table public.custody_events enable row level security;
alter table public.case_audit_events enable row level security;

alter table public.cases force row level security;
alter table public.case_memberships force row level security;
alter table public.member_public_keys force row level security;
alter table public.member_key_vaults force row level security;
alter table public.case_key_envelopes force row level security;
alter table public.evidence_records force row level security;
alter table public.evidence_hashes force row level security;
alter table public.custody_events force row level security;
alter table public.case_audit_events force row level security;

create policy cases_member_read on public.cases
  for select to authenticated
  using (public.has_case_role(id, array['admin', 'investigator', 'viewer']::public.case_role[]));

create policy memberships_member_read on public.case_memberships
  for select to authenticated
  using (public.has_case_role(case_id, array['admin', 'investigator', 'viewer']::public.case_role[]));

create policy public_keys_authenticated_read on public.member_public_keys
  for select to authenticated using (true);
create policy public_keys_owner_insert on public.member_public_keys
  for insert to authenticated with check (user_id = auth.uid());
create policy public_keys_owner_update on public.member_public_keys
  for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

create policy private_key_vault_owner_read on public.member_key_vaults
  for select to authenticated using (user_id = auth.uid());
create policy private_key_vault_owner_insert on public.member_key_vaults
  for insert to authenticated with check (user_id = auth.uid());
create policy private_key_vault_owner_update on public.member_key_vaults
  for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

create policy case_envelope_owner_read on public.case_key_envelopes
  for select to authenticated
  using (user_id = auth.uid() and public.has_case_role(case_id, array['admin', 'investigator', 'viewer']::public.case_role[]));

create policy evidence_member_read on public.evidence_records
  for select to authenticated
  using (
    public.has_case_role(case_id, array['admin', 'investigator', 'viewer']::public.case_role[])
    and (upload_status = 'uploaded' or reserved_by = auth.uid())
  );

create policy evidence_hash_member_read on public.evidence_hashes
  for select to authenticated
  using (public.has_case_role(case_id, array['admin', 'investigator', 'viewer']::public.case_role[]));
create policy custody_member_read on public.custody_events
  for select to authenticated
  using (public.has_case_role(case_id, array['admin', 'investigator', 'viewer']::public.case_role[]));

create policy case_audit_member_read on public.case_audit_events
  for select to authenticated
  using (public.has_case_role(case_id, array['admin', 'investigator', 'viewer']::public.case_role[]));

grant usage on type public.case_role to authenticated;
revoke all on table public.cases, public.case_memberships, public.member_public_keys,
  public.member_key_vaults, public.case_key_envelopes, public.evidence_records,
  public.evidence_hashes, public.custody_events, public.case_audit_events
  from anon, authenticated;
grant select on public.cases, public.case_memberships, public.case_key_envelopes,
  public.evidence_records, public.evidence_hashes, public.custody_events,
  public.case_audit_events to authenticated;
grant select, insert, update on public.member_public_keys, public.member_key_vaults to authenticated;
revoke insert, update, delete on public.evidence_hashes from authenticated;

revoke all on function public.has_case_role(uuid, public.case_role[]) from public, anon;
revoke all on function public.has_storage_case_role(text, public.case_role[]) from public, anon;
revoke all on function public.can_upload_storage_object(text) from public, anon;
revoke all on function public.prevent_forensic_delete() from public, anon;
revoke all on function public.submit_evidence_hash(uuid, text, timestamptz) from public, anon;
revoke all on function public.reserve_evidence_upload(uuid, bytea, text, timestamptz) from public, anon;
revoke all on function public.complete_evidence_upload(uuid) from public, anon;
revoke all on function public.verify_evidence_hash(uuid, text) from public, anon;
revoke all on function public.create_case(text, bytea, jsonb) from public, anon;
revoke all on function public.add_case_member(uuid, uuid, public.case_role, jsonb) from public, anon;
revoke all on function public.change_case_member_role(uuid, uuid, public.case_role) from public, anon;
revoke all on function public.remove_case_member(uuid, uuid) from public, anon;
revoke all on function public.archive_case(uuid) from public, anon;
revoke all on function public.archive_evidence_record(uuid) from public, anon;
revoke all on function public.resolve_case_member_offboarding(uuid, uuid) from public, anon;
revoke all on function public.append_custody_event(uuid, text, bytea) from public, anon;
grant execute on function public.has_case_role(uuid, public.case_role[]) to authenticated;
grant execute on function public.has_storage_case_role(text, public.case_role[]) to anon, authenticated;
grant execute on function public.can_upload_storage_object(text) to anon, authenticated;
grant usage on type public.case_role to anon;
grant execute on function public.submit_evidence_hash(uuid, text, timestamptz) to authenticated;
grant execute on function public.reserve_evidence_upload(uuid, bytea, text, timestamptz) to authenticated;
grant execute on function public.complete_evidence_upload(uuid) to authenticated;
grant execute on function public.verify_evidence_hash(uuid, text) to authenticated;
grant execute on function public.create_case(text, bytea, jsonb) to authenticated;
grant execute on function public.add_case_member(uuid, uuid, public.case_role, jsonb) to authenticated;
grant execute on function public.change_case_member_role(uuid, uuid, public.case_role) to authenticated;
grant execute on function public.remove_case_member(uuid, uuid) to authenticated;
grant execute on function public.archive_case(uuid) to authenticated;
grant execute on function public.archive_evidence_record(uuid) to authenticated;
grant execute on function public.resolve_case_member_offboarding(uuid, uuid) to authenticated;
grant execute on function public.append_custody_event(uuid, text, bytea) to authenticated;

insert into storage.buckets (id, name, public)
values ('forensiai-evidence', 'forensiai-evidence', false)
on conflict (id) do update set public = false;

create policy forensiai_evidence_member_read on storage.objects
  for select to authenticated
  using (
    bucket_id = 'forensiai-evidence'
    and public.has_storage_case_role(name, array['admin', 'investigator', 'viewer']::public.case_role[])
  );

create policy forensiai_evidence_read_guard on storage.objects as restrictive
  for select to public
  using (
    bucket_id <> 'forensiai-evidence'
    or public.has_storage_case_role(name, array['admin', 'investigator', 'viewer']::public.case_role[])
  );

create policy forensiai_evidence_writer_upload on storage.objects
  for insert to authenticated
  with check (
    bucket_id = 'forensiai-evidence'
    and public.can_upload_storage_object(name)
  );

create policy forensiai_evidence_upload_guard on storage.objects as restrictive
  for insert to public
  with check (
    bucket_id <> 'forensiai-evidence'
    or public.can_upload_storage_object(name)
  );

create policy forensiai_evidence_update_guard on storage.objects as restrictive
  for update to public
  using (bucket_id <> 'forensiai-evidence')
  with check (bucket_id <> 'forensiai-evidence');

create policy forensiai_evidence_delete_guard on storage.objects as restrictive
  for delete to public
  using (bucket_id <> 'forensiai-evidence');

commit;