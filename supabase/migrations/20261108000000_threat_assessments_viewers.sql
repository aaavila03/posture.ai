-- Viewers can read the threat risk assessments that name them as asset or risk owner. Their
-- name comes from the people directory, which only admins can change: members can edit their
-- own profile, so a profile name could be changed to read someone else's assessment.

create or replace function private.owns_threat_assessment(org uuid, rec jsonb)
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.memberships m
    join public.people p on p.org_id = m.org_id and p.email = lower(m.email)
    where m.org_id = org and m.user_id = auth.uid()
      and lower(btrim(p.first_name || ' ' || p.last_name)) in (lower(btrim(rec ->> 'assetOwner')), lower(btrim(rec ->> 'riskOwner')))
  )
$$;
revoke all on function private.owns_threat_assessment(uuid, jsonb) from public, anon;
grant execute on function private.owns_threat_assessment(uuid, jsonb) to authenticated;

drop policy threat_assessment_select on public.threat_assessments;
create policy threat_assessment_select on public.threat_assessments for select to authenticated
  using (private.has_role(org_id, 'analyst') or (private.has_role(org_id, 'viewer') and private.owns_threat_assessment(org_id, data)));
