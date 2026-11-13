-- Custom fields inside each risk register section (see risk-sections.js): a section is
-- { id, name, fields: [{ id, label, type, options }] }. The column can now hold a few dozen
-- fields, and the admin function checks each field as well as each section.

alter table public.organizations drop constraint if exists organizations_risk_sections_check;
alter table public.organizations add constraint organizations_risk_sections_check check (risk_sections is null or (
  jsonb_typeof(risk_sections) = 'array' and jsonb_array_length(risk_sections) <= 20 and pg_column_size(risk_sections) <= 65536));

create or replace function public.set_org_risk_sections(org uuid, sections jsonb)
returns void language plpgsql security definer set search_path = '' as $$
begin
  perform private.require_role(org, 'admin');
  if sections is null or jsonb_typeof(sections) <> 'array' then raise exception 'sections must be a list'; end if;
  if exists (select 1 from jsonb_array_elements(sections) s
    where jsonb_typeof(s) <> 'object' or coalesce(s ->> 'id', '') !~ '^[a-z0-9]{1,20}$'
      or char_length(btrim(coalesce(s ->> 'name', ''))) not between 1 and 60
      or (s ? 'fields' and (jsonb_typeof(s -> 'fields') <> 'array' or jsonb_array_length(s -> 'fields') > 30))) then
    raise exception 'each section needs an id, a name and a list of fields';
  end if;
  if exists (select 1 from jsonb_array_elements(sections) s, jsonb_array_elements(coalesce(s -> 'fields', '[]'::jsonb)) f
    where jsonb_typeof(f) <> 'object' or coalesce(f ->> 'id', '') !~ '^[a-z0-9]{1,20}$'
      or char_length(btrim(coalesce(f ->> 'label', ''))) not between 1 and 60
      or coalesce(f ->> 'type', '') not in ('text', 'longtext', 'number', 'yesno', 'date', 'picklist')) then
    raise exception 'each field needs an id, a name and a known type';
  end if;
  update public.organizations set risk_sections = sections where id = org;
end $$;

revoke all on function public.set_org_risk_sections(uuid, jsonb) from public, anon;
grant execute on function public.set_org_risk_sections(uuid, jsonb) to authenticated;
