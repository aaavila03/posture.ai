-- Editing the people directory one person at a time (Settings → People directory),
-- alongside file imports. Admins only; recorded in the audit log.

-- Adds or updates one person. previous_email is their current email when it's being changed;
-- anyone who reported to the old email then reports to the new one. A manager can't be the
-- person themselves or anyone below them.
create or replace function public.save_person(org uuid, person jsonb, previous_email text default null)
returns void language plpgsql security definer set search_path = '' as $$
declare
  addr text := lower(btrim(coalesce(person ->> 'email', '')));
  prev text := nullif(lower(btrim(coalesce(previous_email, ''))), '');
  mgr text := lower(btrim(coalesce(person ->> 'manager_email', '')));
begin
  perform private.require_role(org, 'admin');
  if mgr <> '' and not exists (select 1 from public.people p where p.org_id = org and p.email = mgr) then
    raise exception 'the manager isn''t in the directory';
  end if;
  if mgr <> '' and (mgr = addr or mgr = prev or exists (
    with recursive up (email, depth) as (
      select p.manager_email, 1 from public.people p where p.org_id = org and p.email = mgr
      union all
      select p.manager_email, u.depth + 1 from up u join public.people p on p.org_id = org and p.email = u.email
      where u.email <> '' and u.depth < 100
    )
    select 1 from up where up.email in (addr, prev)
  )) then
    raise exception 'a person can''t report to themselves or to someone below them';
  end if;
  if prev is not null and prev <> addr then
    if exists (select 1 from public.people p where p.org_id = org and p.email = addr) then
      raise exception 'someone in the directory already has that email';
    end if;
    update public.people p set email = addr where p.org_id = org and p.email = prev;
    update public.people p set manager_email = addr where p.org_id = org and p.manager_email = prev;
  end if;
  insert into public.people as p (org_id, email, first_name, last_name, title, department, phone, manager_email, updated_at, updated_by)
  values (org, addr, btrim(coalesce(person ->> 'first_name', '')), btrim(coalesce(person ->> 'last_name', '')),
          btrim(coalesce(person ->> 'title', '')), btrim(coalesce(person ->> 'department', '')),
          btrim(coalesce(person ->> 'phone', '')), mgr, now(), auth.uid())
  on conflict (org_id, email) do update set
    first_name = excluded.first_name, last_name = excluded.last_name, title = excluded.title, department = excluded.department,
    phone = excluded.phone, manager_email = excluded.manager_email, updated_at = now(), updated_by = auth.uid();
  perform private.write_audit(org, case when prev is null then 'save' else 'update' end, 'people', addr, null);
end $$;

-- Removes one person; the people who reported to them move up to their manager.
create or replace function public.delete_person(org uuid, person_email text)
returns void language plpgsql security definer set search_path = '' as $$
declare
  addr text := lower(btrim(coalesce(person_email, '')));
  mgr text := (select p.manager_email from public.people p where p.org_id = org and p.email = addr);
begin
  perform private.require_role(org, 'admin');
  if mgr is null then raise exception 'not in the directory'; end if;
  update public.people p set manager_email = mgr where p.org_id = org and p.manager_email = addr;
  delete from public.people p where p.org_id = org and p.email = addr;
  perform private.write_audit(org, 'delete', 'people', addr, null);
end $$;

revoke all on function public.save_person(uuid, jsonb, text), public.delete_person(uuid, text) from public, anon;
grant execute on function public.save_person(uuid, jsonb, text), public.delete_person(uuid, text) to authenticated;
