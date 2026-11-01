-- People directory: the organisation's hierarchy (name, title, department, manager),
-- imported by admins from a CSV or Excel file. Owner fields on risks and vendors are
-- picked from it. Being in the directory doesn't give app access; admins invite
-- people separately. Everyone in the workspace can read it; only admins change it.

create table public.people (
  org_id uuid not null references public.organizations (id) on delete cascade,
  email text not null check (email = lower(email) and email ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' and char_length(email) <= 254),
  first_name text not null default '' check (char_length(first_name) <= 80),
  last_name text not null default '' check (char_length(last_name) <= 80),
  title text not null default '' check (char_length(title) <= 120),
  department text not null default '' check (char_length(department) <= 120),
  phone text not null default '' check (phone ~ '^[0-9+()./ x-]{0,40}$'),
  manager_email text not null default '' check (manager_email = lower(manager_email) and char_length(manager_email) <= 254),
  updated_at timestamptz not null default now(),
  updated_by uuid,
  primary key (org_id, email),
  check (first_name <> '' or last_name <> '')
);

alter table public.people enable row level security;
create policy people_select on public.people for select to authenticated using (private.has_role(org_id, 'viewer'));
revoke all on public.people from anon, authenticated;
grant select on public.people to authenticated;

-- The people in an import file (a JSON array), cleaned up: one row per email.
create or replace function private.people_rows(rows jsonb)
returns table (email text, first_name text, last_name text, title text, department text, phone text, manager_email text)
language sql immutable set search_path = '' as $$
  select distinct on (lower(btrim(r ->> 'email')))
    lower(btrim(r ->> 'email')),
    btrim(coalesce(r ->> 'first_name', '')),
    btrim(coalesce(r ->> 'last_name', '')),
    btrim(coalesce(r ->> 'title', '')),
    btrim(coalesce(r ->> 'department', '')),
    btrim(coalesce(r ->> 'phone', '')),
    nullif(lower(btrim(coalesce(r ->> 'manager_email', ''))), lower(btrim(r ->> 'email')))
  from jsonb_array_elements(rows) r
  where jsonb_typeof(r) = 'object' and coalesce(btrim(r ->> 'email'), '') <> ''
$$;

-- Adds or updates the people in rows (a JSON array, up to 5,000). With replace, anyone
-- not in rows is removed. Returns how many people the directory now holds.
create or replace function public.import_people(org uuid, rows jsonb, replace boolean default false)
returns integer language plpgsql security definer set search_path = '' as $$
declare
  n integer;
begin
  perform private.require_role(org, 'admin');
  if jsonb_typeof(rows) is distinct from 'array' then raise exception 'rows must be a list'; end if;
  if jsonb_array_length(rows) > 5000 then raise exception 'at most 5,000 people per import'; end if;

  if replace then
    delete from public.people p where p.org_id = org and p.email not in (select i.email from private.people_rows(rows) i);
  end if;
  insert into public.people as p (org_id, email, first_name, last_name, title, department, phone, manager_email, updated_at, updated_by)
  select org, i.email, i.first_name, i.last_name, i.title, i.department, i.phone, coalesce(i.manager_email, ''), now(), auth.uid()
  from private.people_rows(rows) i
  on conflict (org_id, email) do update set
    first_name = excluded.first_name, last_name = excluded.last_name, title = excluded.title, department = excluded.department,
    phone = excluded.phone, manager_email = excluded.manager_email, updated_at = now(), updated_by = auth.uid();

  select count(*) into n from public.people p where p.org_id = org;
  perform private.write_audit(org, 'import', 'people', null,
    jsonb_build_object('rows', (select count(*) from private.people_rows(rows)), 'replace', replace, 'total', n));
  return n;
end $$;

-- Removes everyone from the directory (admins).
create or replace function public.clear_people(org uuid)
returns void language plpgsql security definer set search_path = '' as $$
begin
  perform private.require_role(org, 'admin');
  delete from public.people p where p.org_id = org;
  perform private.write_audit(org, 'delete', 'people', 'all', null);
end $$;

revoke all on function public.import_people(uuid, jsonb, boolean), public.clear_people(uuid), private.people_rows(jsonb) from public, anon;
grant execute on function public.import_people(uuid, jsonb, boolean), public.clear_people(uuid) to authenticated;
