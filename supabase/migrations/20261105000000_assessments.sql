-- Ad-hoc risk assessments: a cybersecurity review of a solution or technology (scope,
-- evidence, data handling, cloud / AI / OT / NERC CIP considerations, findings,
-- recommendations, determination and sign-off). Same access as risks: everyone in the
-- workspace reads them, analysts and above add, edit and delete them.

create table public.assessments (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id) on delete cascade,
  display_id text not null check (display_id ~ '^A-[0-9]{3,6}$'),
  data jsonb not null check (jsonb_typeof(data) = 'object' and pg_column_size(data) <= 262144),
  created_at timestamptz not null default now(),
  created_by uuid,
  updated_at timestamptz not null default now(),
  updated_by uuid,
  unique (org_id, display_id)
);

create trigger assessments_stamp before insert or update on public.assessments for each row execute function private.stamp_record();
create trigger assessments_audit after insert or update or delete on public.assessments for each row execute function private.audit_record();

alter table public.assessments enable row level security;
create policy assessment_select on public.assessments for select to authenticated using (private.has_role(org_id, 'viewer'));
create policy assessment_insert on public.assessments for insert to authenticated with check (private.has_role(org_id, 'analyst'));
create policy assessment_update on public.assessments for update to authenticated
  using (private.has_role(org_id, 'analyst')) with check (private.has_role(org_id, 'analyst'));
create policy assessment_delete on public.assessments for delete to authenticated using (private.has_role(org_id, 'analyst'));

revoke all on public.assessments from anon, authenticated;
grant select, delete on public.assessments to authenticated;
grant insert (org_id, display_id, data) on public.assessments to authenticated;
grant update (data) on public.assessments to authenticated;
