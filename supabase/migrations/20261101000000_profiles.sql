-- Member profiles: first and last name, title, phone and department.
-- Anyone can read the profiles of people who share a workspace with them.
-- People edit their own profile; admins edit the profiles of their workspace's
-- members. Details entered on an invitation become the new member's profile.

create table public.profiles (
  user_id uuid primary key references auth.users (id) on delete cascade,
  first_name text not null default '' check (char_length(first_name) <= 80),
  last_name text not null default '' check (char_length(last_name) <= 80),
  title text not null default '' check (char_length(title) <= 120),
  phone text not null default '' check (phone ~ '^[0-9+()./ x-]{0,40}$'),
  department text not null default '' check (char_length(department) <= 120),
  updated_at timestamptz not null default now(),
  updated_by uuid
);

alter table public.invitations add column profile jsonb
  check (profile is null or (jsonb_typeof(profile) = 'object' and pg_column_size(profile) <= 4096));

-- True when the caller (on an MFA session) and the given user are members of a common organisation.
create or replace function private.shares_org(member uuid)
returns boolean language sql stable security definer set search_path = '' as $$
  select private.mfa_ok() and exists (
    select 1 from public.memberships a join public.memberships b on b.org_id = a.org_id
    where a.user_id = auth.uid() and b.user_id = member
  )
$$;

alter table public.profiles enable row level security;
create policy profile_select on public.profiles for select to authenticated
  using (user_id = auth.uid() or private.shares_org(user_id));
revoke all on public.profiles from anon, authenticated;
grant select on public.profiles to authenticated;

-- Saves a profile: your own, or (as an admin of org) one of org's members'. Recorded in org's audit log.
create or replace function public.save_profile(org uuid, member uuid, first_name text, last_name text, title text, phone text, department text)
returns void language plpgsql security definer set search_path = '' as $$
declare
  member_email text := (select m.email from public.memberships m where m.org_id = org and m.user_id = member);
begin
  if member_email is null then raise exception 'not a member of this workspace'; end if;
  if member = auth.uid() then
    perform private.require_role(org, 'viewer');
  else
    perform private.require_role(org, 'admin');
  end if;
  insert into public.profiles as p (user_id, first_name, last_name, title, phone, department, updated_at, updated_by)
  values (member, btrim(coalesce(first_name, '')), btrim(coalesce(last_name, '')), btrim(coalesce(title, '')),
          btrim(coalesce(phone, '')), btrim(coalesce(department, '')), now(), auth.uid())
  on conflict (user_id) do update set
    first_name = excluded.first_name, last_name = excluded.last_name, title = excluded.title,
    phone = excluded.phone, department = excluded.department, updated_at = now(), updated_by = auth.uid();
  perform private.write_audit(org, 'update', 'profiles', member_email, null);
end $$;

-- Attaches profile details to a pending invitation (admins), applied when it's accepted.
create or replace function public.set_invitation_profile(invitation uuid, details jsonb)
returns void language plpgsql security definer set search_path = '' as $$
declare org uuid := (select i.org_id from public.invitations i where i.id = invitation and i.accepted_at is null);
begin
  perform private.require_role(org, 'admin');
  update public.invitations i set profile = jsonb_build_object(
    'first_name', left(coalesce(details ->> 'first_name', ''), 80),
    'last_name', left(coalesce(details ->> 'last_name', ''), 80),
    'title', left(coalesce(details ->> 'title', ''), 120),
    'phone', left(coalesce(details ->> 'phone', ''), 40),
    'department', left(coalesce(details ->> 'department', ''), 120))
  where i.id = invitation;
end $$;

-- As before, plus: a new member without a profile gets the details from their invitation.
create or replace function public.accept_invitations()
returns integer language plpgsql security definer set search_path = '' as $$
declare
  addr text;
  n integer := 0;
  inv record;
begin
  if auth.uid() is null or not private.mfa_ok() then
    raise exception 'multi-factor authentication required' using errcode = '42501';
  end if;
  select lower(u.email) into addr from auth.users u where u.id = auth.uid() and u.email_confirmed_at is not null;
  if addr is null then return 0; end if;
  for inv in
    select * from public.invitations i where i.email = addr and i.accepted_at is null and i.expires_at > now() for update
  loop
    insert into public.memberships (org_id, user_id, role, email)
    values (inv.org_id, auth.uid(), inv.role, addr)
    on conflict (org_id, user_id) do nothing;
    update public.invitations set accepted_at = now() where id = inv.id;
    if inv.profile is not null then
      begin
        insert into public.profiles (user_id, first_name, last_name, title, phone, department, updated_by)
        values (auth.uid(), btrim(inv.profile ->> 'first_name'), btrim(inv.profile ->> 'last_name'), btrim(inv.profile ->> 'title'),
                btrim(inv.profile ->> 'phone'), btrim(inv.profile ->> 'department'), inv.invited_by)
        on conflict (user_id) do nothing;
      exception when check_violation then null; -- a malformed phone number shouldn't block joining
      end;
    end if;
    n := n + 1;
  end loop;
  return n;
end $$;

revoke all on function public.save_profile(uuid, uuid, text, text, text, text, text), public.set_invitation_profile(uuid, jsonb),
  private.shares_org(uuid) from public, anon;
grant execute on function public.save_profile(uuid, uuid, text, text, text, text, text), public.set_invitation_profile(uuid, jsonb),
  private.shares_org(uuid) to authenticated;
