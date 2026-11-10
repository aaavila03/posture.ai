-- The NIST framework a workspace's threat risk assessments follow: CSF 2.0 or SP 800-53.
-- It sets how the app groups and references security controls (see tra.js). New workspaces
-- choose it when they're created; ones created before this stay unset until an admin chooses.
alter table public.organizations add column tra_framework text
  check (tra_framework in ('csf2', 'sp80053'));

-- Creating a workspace now includes the framework.
drop function public.create_organization(text);
create function public.create_organization(org_name text, framework text)
returns uuid language plpgsql security definer set search_path = '' as $$
declare
  new_id uuid;
  caller_email text := (select u.email from auth.users u where u.id = auth.uid());
begin
  if auth.uid() is null or not private.mfa_ok() then
    raise exception 'multi-factor authentication required' using errcode = '42501';
  end if;
  if framework is null or framework not in ('csf2', 'sp80053') then
    raise exception 'choose a framework for threat risk assessments';
  end if;
  if (select count(*) from public.memberships m where m.user_id = auth.uid() and m.role = 'owner') >= 5 then
    raise exception 'organisation limit reached';
  end if;
  insert into public.organizations (name, created_by, tra_framework) values (btrim(org_name), auth.uid(), framework) returning id into new_id;
  insert into public.memberships (org_id, user_id, role, email) values (new_id, auth.uid(), 'owner', coalesce(caller_email, ''));
  return new_id;
end $$;

-- Admins and owners change it. Members read it through org_select.
create or replace function public.set_org_tra_framework(org uuid, framework text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  perform private.require_role(org, 'admin');
  if framework is null or framework not in ('csf2', 'sp80053') then
    raise exception 'unknown framework';
  end if;
  update public.organizations set tra_framework = framework where id = org;
end $$;

revoke all on function public.create_organization(text, text), public.set_org_tra_framework(uuid, text) from public, anon;
grant execute on function public.create_organization(text, text), public.set_org_tra_framework(uuid, text) to authenticated;

-- The outside form groups its controls the same way, so the link also returns the framework.
create or replace function public.tra_outside_load(token text)
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare
  target public.threat_assessments := private.tra_link_target(token);
  hash text := encode(sha256(convert_to(token, 'UTF8')), 'hex');
  shared boolean := (select l.share_existing from public.threat_assessment_links l where l.token_hash = hash);
  saved public.threat_assessment_responses;
  org public.organizations;
begin
  select r.* into saved from public.threat_assessment_responses r where r.token_hash = hash and r.status = 'draft';
  select o.* into org from public.organizations o where o.id = target.org_id;
  return jsonb_build_object(
    'requester', org.name, 'logo', org.logo, 'framework', org.tra_framework, 'assetName', target.data ->> 'assetName',
    'seed', case when shared then jsonb_build_object('description', target.data -> 'description', 'department', target.data -> 'department',
      'profile', target.data -> 'profile', 'answers', target.data -> 'answers') end,
    'response', saved.response - 'contributor', 'updatedAt', saved.updated_at);
end $$;
