-- Change history for risks. Updates to a risk now record, in the audit log, the old and new value of its key fields
-- (details -> 'changes' -> field -> { from, to }) next to the existing list of changed fields (details -> 'changed'),
-- which is unchanged. Only these fields are recorded with values; everything else, including comments and the AI
-- review, appears only in the changed list. Each value is cut to 200 characters.
create or replace function private.audit_record()
returns trigger language plpgsql security definer set search_path = '' as $$
declare
  rec jsonb := to_jsonb(coalesce(new, old));
  changed jsonb;
  changes jsonb;
  ident text := coalesce(rec ->> 'display_id', rec ->> 'email', rec ->> 'user_id', rec ->> 'name', rec ->> 'id');
  key_fields constant text[] := array['title', 'status', 'category', 'owner', 'likelihood', 'impact', 'residualLikelihood', 'residualImpact',
    'treatment', 'due', 'nextReview', 'logException', 'exceptionApproved', 'exceptionExpiry'];
begin
  if tg_op = 'UPDATE' then
    if to_jsonb(new) ? 'data' then
      select coalesce(jsonb_agg(k), '[]'::jsonb) into changed
      from (
        select k from jsonb_object_keys(coalesce(new.data, '{}'::jsonb) || coalesce(old.data, '{}'::jsonb)) k
        where (new.data -> k) is distinct from (old.data -> k)
      ) s;
      if tg_table_name = 'risks' then
        select coalesce(jsonb_object_agg(k, jsonb_build_object(
          'from', left(coalesce(old.data ->> k, ''), 200), 'to', left(coalesce(new.data ->> k, ''), 200))), '{}'::jsonb) into changes
        from unnest(key_fields) k
        where (new.data -> k) is distinct from (old.data -> k);
      end if;
    else
      select coalesce(jsonb_agg(k), '[]'::jsonb) into changed
      from (
        select k from jsonb_object_keys(to_jsonb(new)) k
        where (to_jsonb(new) -> k) is distinct from (to_jsonb(old) -> k)
      ) s;
    end if;
  end if;
  perform private.write_audit(
    coalesce((rec ->> 'org_id')::uuid, (rec ->> 'id')::uuid),
    lower(tg_op),
    tg_table_name,
    ident,
    case
      when tg_op = 'UPDATE' and changes is not null and changes <> '{}'::jsonb then jsonb_build_object('changed', changed, 'changes', changes)
      when tg_op = 'UPDATE' then jsonb_build_object('changed', changed)
      when tg_table_name in ('memberships', 'invitations') then jsonb_build_object('role', rec ->> 'role')
      else null
    end
  );
  return coalesce(new, old);
end $$;

-- One risk's history, newest first: when, who, what happened, and the key fields that changed with their old and new
-- values. Anyone who can read the risks can read this (the audit log itself stays admin-only). Entries from before
-- the risk was last deleted are left out, because a deleted risk's number can be used again.
create or replace function public.risk_history(org uuid, risk text)
returns table (at timestamptz, actor_email text, action text, changes jsonb)
language plpgsql stable security definer set search_path = '' as $$
begin
  perform private.require_role(org, 'viewer');
  return query
    select a.at, a.actor_email, a.action, a.details -> 'changes'
    from public.audit_log a
    where a.org_id = org and a.entity = 'risks' and a.entity_id = risk and a.action in ('insert', 'update')
      and a.id > coalesce((select max(d.id) from public.audit_log d
        where d.org_id = org and d.entity = 'risks' and d.entity_id = risk and d.action = 'delete'), 0)
    order by a.id desc
    limit 100;
end $$;

revoke all on function public.risk_history(uuid, text) from public, anon;
grant execute on function public.risk_history(uuid, text) to authenticated;
