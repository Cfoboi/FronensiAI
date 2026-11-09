begin;

alter table public.case_audit_events
  drop constraint if exists case_audit_events_event_type_check;

alter table public.case_audit_events
  add constraint case_audit_events_event_type_check
  check (event_type in (
    'case_created',
    'case_registered',
    'case_archived',
    'evidence_archived',
    'member_added',
    'member_role_changed',
    'member_removed'
  ));

create or replace function public.register_local_case(p_case_number text)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user_id uuid := auth.uid();
  v_case_id uuid;
  v_case_archived_at timestamptz;
  v_case_number text := btrim(p_case_number);
begin
  if v_user_id is null then
    raise exception using errcode = '42501', message = 'Authentication required.';
  end if;
  if v_case_number is null or length(v_case_number) not between 1 and 120 then
    raise exception using errcode = '22023', message = 'Invalid case number.';
  end if;

  insert into public.cases (case_number, created_by)
  values (v_case_number, v_user_id)
  on conflict (case_number) do nothing
  returning id into v_case_id;

  if v_case_id is null then
    select id, archived_at into v_case_id, v_case_archived_at
    from public.cases
    where case_number = v_case_number;

    if v_case_id is null
      or v_case_archived_at is not null
      or not exists (
        select 1
        from public.case_memberships
        where case_id = v_case_id
          and user_id = v_user_id
          and is_active
      ) then
      raise exception using errcode = '42501', message = 'This case is already registered and is not available to your account.';
    end if;

    return v_case_id;
  end if;

  insert into public.case_memberships (case_id, user_id, role, is_active, invited_by)
  values (v_case_id, v_user_id, 'admin', true, v_user_id);

  insert into public.case_audit_events (case_id, actor_id, target_user_id, event_type)
  values (v_case_id, v_user_id, v_user_id, 'case_registered');

  return v_case_id;
end;
$$;

revoke all on function public.register_local_case(text) from public, anon;
grant execute on function public.register_local_case(text) to authenticated;

commit;
