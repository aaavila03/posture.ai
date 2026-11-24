-- Risk exceptions become a process: an analyst or above requests an exception (a reason and an expiry date), someone with
-- the approver role or above, who is not the requester, approves or rejects it, and an exception is renewed by requesting
-- it again. Approvers and above can revoke an approved exception. Every step is kept and audited.
--
-- The roles now rank viewer < analyst < approver < admin < owner. Everything that asks for 'analyst' or 'admin' keeps working,
-- since it compares ranks; approvers can do all that analysts can, and admins and owners can approve.

create or replace function private.role_rank(r public.member_role)
returns integer language sql immutable set search_path = '' as $$
  select case r when 'viewer' then 1 when 'analyst' then 2 when 'approver' then 3 when 'admin' then 4 when 'owner' then 5 end
$$;

-- ---------------------------------------------------------------------------
-- The requests (and their decisions), one row each. Nobody writes this table directly: only the functions below do.
-- ---------------------------------------------------------------------------
create table public.risk_exceptions (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id) on delete cascade,
  risk_ref text not null check (risk_ref ~ '^R-[0-9]{3,6}$'),
  renewal boolean not null default false,
  reason text not null check (char_length(btrim(reason)) between 1 and 2000),
  proposed_expiry date not null,
  status text not null default 'requested' check (status in ('requested', 'approved', 'rejected', 'withdrawn')),
  requested_by uuid not null,
  requested_by_email text not null,
  requested_at timestamptz not null default now(),
  decided_by uuid,
  decided_by_email text,
  decided_at timestamptz,
  decision_note text check (decision_note is null or char_length(decision_note) <= 2000),
  check ((status = 'requested') = (decided_at is null))
);
create index risk_exceptions_risk_idx on public.risk_exceptions (org_id, risk_ref, requested_at desc);
-- A risk has at most one request awaiting a decision.
create unique index risk_exceptions_one_open on public.risk_exceptions (org_id, risk_ref) where status = 'requested';

alter table public.risk_exceptions enable row level security;
create policy risk_exception_select on public.risk_exceptions for select to authenticated using (private.has_role(org_id, 'viewer'));
revoke all on public.risk_exceptions from anon, authenticated;
grant select on public.risk_exceptions to authenticated;

-- ---------------------------------------------------------------------------
-- The approval fields on a risk can only be changed by the functions below. A client that writes them (an analyst saving
-- a risk, an import, a stale copy of the risk) has them put back as they were, or left out of a new risk. Only a database
-- role other than the API roles, such as the owner of the functions below, can change them.
-- ---------------------------------------------------------------------------
create or replace function private.risks_exception_fields()
returns trigger language plpgsql set search_path = '' as $$
declare
  keys constant text[] := array['exceptionApproved', 'exceptionExpiry', 'exceptionApprovedBy', 'exceptionApprovedDate', 'exceptionPending'];
begin
  if current_user not in ('authenticated', 'anon') then
    return new;
  end if;
  if tg_op = 'INSERT' then
    new.data := new.data - keys;
  else
    new.data := (new.data - keys) || coalesce((select jsonb_object_agg(k, old.data -> k) from unnest(keys) k where old.data ? k), '{}'::jsonb);
  end if;
  return new;
end $$;
create trigger risks_exception_fields before insert or update on public.risks
  for each row execute function private.risks_exception_fields();

-- Sets and clears approval fields on a risk (the functions below run as the table owner, so the trigger above lets them).
create or replace function private.set_risk_exception_fields(org uuid, risk text, add_fields jsonb, drop_fields text[])
returns void language sql security definer set search_path = '' as $$
  update public.risks r set data = (r.data - drop_fields) || add_fields where r.org_id = org and r.display_id = risk
$$;

create or replace function private.caller_email()
returns text language sql stable set search_path = '' as $$
  select coalesce(auth.jwt() ->> 'email', '')
$$;

-- ---------------------------------------------------------------------------
-- Request an exception (or its renewal): analysts and above.
-- ---------------------------------------------------------------------------
create or replace function public.request_exception(org uuid, risk text, reason text, expiry date)
returns uuid language plpgsql security definer set search_path = '' as $$
declare
  current_data jsonb;
  req uuid;
begin
  perform private.require_role(org, 'analyst');
  select r.data into current_data from public.risks r where r.org_id = org and r.display_id = risk for update;
  if current_data is null then raise exception 'that risk does not exist'; end if;
  if reason is null or btrim(reason) = '' then raise exception 'give a reason for the exception'; end if;
  if expiry is null or expiry <= current_date then raise exception 'the expiry date must be in the future'; end if;
  if expiry > current_date + 730 then raise exception 'an exception can last at most two years'; end if;
  begin
    insert into public.risk_exceptions (org_id, risk_ref, renewal, reason, proposed_expiry, requested_by, requested_by_email)
    values (org, risk, (current_data ->> 'exceptionApproved') = 'Yes', btrim(reason), expiry, auth.uid(), private.caller_email())
    returning id into req;
  exception when unique_violation then
    raise exception 'this risk already has a request waiting for a decision';
  end;
  perform private.set_risk_exception_fields(org, risk, jsonb_build_object('logException', 'Yes', 'exceptionPending', to_char(current_date, 'YYYY-MM-DD')), array[]::text[]);
  return req;
end $$;

-- ---------------------------------------------------------------------------
-- Decide a request: approvers and above, and never the person who made it. A rejection needs a note.
-- ---------------------------------------------------------------------------
create or replace function public.decide_exception(org uuid, request uuid, approve boolean, note text)
returns void language plpgsql security definer set search_path = '' as $$
declare
  req public.risk_exceptions;
  current_data jsonb;
  who text := private.caller_email();
begin
  perform private.require_role(org, 'approver');
  select * into req from public.risk_exceptions e where e.id = request and e.org_id = org for update;
  if req.id is null then raise exception 'that request does not exist'; end if;
  if req.status <> 'requested' then raise exception 'that request has already been decided'; end if;
  if req.requested_by = auth.uid() then
    raise exception 'someone else must decide a request you made' using errcode = '42501';
  end if;
  if not approve and (note is null or btrim(note) = '') then raise exception 'give a reason for rejecting the request'; end if;
  update public.risk_exceptions set status = case when approve then 'approved' else 'rejected' end,
    decided_by = auth.uid(), decided_by_email = who, decided_at = now(), decision_note = nullif(btrim(coalesce(note, '')), '')
    where id = req.id;
  select r.data into current_data from public.risks r where r.org_id = org and r.display_id = req.risk_ref;
  if approve then
    perform private.set_risk_exception_fields(org, req.risk_ref, jsonb_build_object('exceptionApproved', 'Yes', 'exceptionExpiry', to_char(req.proposed_expiry, 'YYYY-MM-DD'),
      'exceptionApprovedBy', who, 'exceptionApprovedDate', to_char(current_date, 'YYYY-MM-DD')), array['exceptionPending']);
  elsif (current_data ->> 'exceptionApproved') is distinct from 'Yes' then
    perform private.set_risk_exception_fields(org, req.risk_ref, jsonb_build_object('exceptionApproved', 'No'), array['exceptionPending']);
  else
    -- A rejected renewal leaves the earlier approval to run out on its own date.
    perform private.set_risk_exception_fields(org, req.risk_ref, '{}'::jsonb, array['exceptionPending']);
  end if;
end $$;

-- ---------------------------------------------------------------------------
-- Withdraw a request that is still waiting: the person who made it, or an admin or owner.
-- ---------------------------------------------------------------------------
create or replace function public.withdraw_exception(org uuid, request uuid)
returns void language plpgsql security definer set search_path = '' as $$
declare
  req public.risk_exceptions;
begin
  perform private.require_role(org, 'analyst');
  select * into req from public.risk_exceptions e where e.id = request and e.org_id = org for update;
  if req.id is null then raise exception 'that request does not exist'; end if;
  if req.status <> 'requested' then raise exception 'that request has already been decided'; end if;
  if req.requested_by <> auth.uid() and not private.has_role(org, 'admin') then
    raise exception 'only the person who made a request, or an admin, can withdraw it' using errcode = '42501';
  end if;
  update public.risk_exceptions set status = 'withdrawn', decided_by = auth.uid(), decided_by_email = private.caller_email(), decided_at = now() where id = req.id;
  perform private.set_risk_exception_fields(org, req.risk_ref, '{}'::jsonb, array['exceptionPending']);
end $$;

-- ---------------------------------------------------------------------------
-- End an approved exception early: approvers and above, with a note. The approval, its date and its expiry are cleared.
-- ---------------------------------------------------------------------------
create or replace function public.revoke_exception(org uuid, risk text, note text)
returns void language plpgsql security definer set search_path = '' as $$
declare
  current_data jsonb;
begin
  perform private.require_role(org, 'approver');
  select r.data into current_data from public.risks r where r.org_id = org and r.display_id = risk for update;
  if current_data is null then raise exception 'that risk does not exist'; end if;
  if (current_data ->> 'exceptionApproved') is distinct from 'Yes' then raise exception 'this risk has no approved exception'; end if;
  if note is null or btrim(note) = '' then raise exception 'give a reason for revoking the exception'; end if;
  perform private.set_risk_exception_fields(org, risk, jsonb_build_object('exceptionApproved', 'No'), array['exceptionExpiry', 'exceptionApprovedBy', 'exceptionApprovedDate']);
  perform private.write_audit(org, 'revoke', 'risk_exceptions', risk, jsonb_build_object('note', left(btrim(note), 500)));
end $$;

revoke all on function public.request_exception(uuid, text, text, date), public.decide_exception(uuid, uuid, boolean, text),
  public.withdraw_exception(uuid, uuid), public.revoke_exception(uuid, text, text) from public, anon;
grant execute on function public.request_exception(uuid, text, text, date), public.decide_exception(uuid, uuid, boolean, text),
  public.withdraw_exception(uuid, uuid), public.revoke_exception(uuid, text, text) to authenticated;
revoke all on function private.set_risk_exception_fields(uuid, text, jsonb, text[]), private.caller_email() from public, anon;
grant execute on function private.caller_email() to authenticated;

-- ---------------------------------------------------------------------------
-- Audit, and a deleted risk takes its requests with it (a new risk can be given the same number).
-- ---------------------------------------------------------------------------
create or replace function private.risk_exceptions_audit()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  perform private.write_audit(new.org_id, lower(tg_op), 'risk_exceptions', new.risk_ref,
    jsonb_build_object('status', new.status, 'renewal', new.renewal, 'proposed_expiry', new.proposed_expiry));
  return new;
end $$;
create trigger risk_exceptions_audit after insert or update on public.risk_exceptions
  for each row execute function private.risk_exceptions_audit();

create or replace function private.risk_exceptions_cleanup()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  delete from public.risk_exceptions e where e.org_id = old.org_id and e.risk_ref = old.display_id;
  return old;
end $$;
create trigger risks_exceptions_cleanup after delete on public.risks
  for each row execute function private.risk_exceptions_cleanup();
