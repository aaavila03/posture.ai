-- Threat risk assessments: one asset's impact rating, profile, control answers and scored
-- control gaps. A list of gaps shows where an asset is weak, so only analysts and above can
-- read them, as with vendors. The app hides the tab from viewers to match.

create table public.threat_assessments (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id) on delete cascade,
  display_id text not null check (display_id ~ '^T-[0-9]{3,6}$'),
  data jsonb not null check (jsonb_typeof(data) = 'object' and pg_column_size(data) <= 1048576),
  created_at timestamptz not null default now(),
  created_by uuid,
  updated_at timestamptz not null default now(),
  updated_by uuid,
  unique (org_id, display_id)
);

create trigger threat_assessments_stamp before insert or update on public.threat_assessments for each row execute function private.stamp_record();
create trigger threat_assessments_audit after insert or update or delete on public.threat_assessments for each row execute function private.audit_record();

alter table public.threat_assessments enable row level security;
create policy threat_assessment_select on public.threat_assessments for select to authenticated using (private.has_role(org_id, 'analyst'));
create policy threat_assessment_insert on public.threat_assessments for insert to authenticated with check (private.has_role(org_id, 'analyst'));
create policy threat_assessment_update on public.threat_assessments for update to authenticated
  using (private.has_role(org_id, 'analyst')) with check (private.has_role(org_id, 'analyst'));
create policy threat_assessment_delete on public.threat_assessments for delete to authenticated using (private.has_role(org_id, 'analyst'));

revoke all on public.threat_assessments from anon, authenticated;
grant select, delete on public.threat_assessments to authenticated;
grant insert (org_id, display_id, data) on public.threat_assessments to authenticated;
grant update (data) on public.threat_assessments to authenticated;
