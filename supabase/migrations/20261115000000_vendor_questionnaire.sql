-- A workspace's own version of the vendor intake questionnaire: built-in questions reworded
-- or turned off, plus its own questions and sections (see cleanCustomization in
-- intake-questions.js, which checks the contents wherever they're used). Null means the
-- built-in questionnaire.
alter table public.organizations add column vendor_questionnaire jsonb
  check (vendor_questionnaire is null
    or (jsonb_typeof(vendor_questionnaire) = 'object' and pg_column_size(vendor_questionnaire) <= 200000));

-- Admins and owners change it (null goes back to the built-in questionnaire). Members read it
-- through org_select, and the vendor's form gets it through the intake-ai function.
create or replace function public.set_org_vendor_questionnaire(org uuid, questionnaire jsonb)
returns void language plpgsql security definer set search_path = '' as $$
begin
  perform private.require_role(org, 'admin');
  update public.organizations
  set vendor_questionnaire = nullif(set_org_vendor_questionnaire.questionnaire, 'null'::jsonb)
  where id = org;
end $$;

revoke all on function public.set_org_vendor_questionnaire(uuid, jsonb) from public, anon;
grant execute on function public.set_org_vendor_questionnaire(uuid, jsonb) to authenticated;
