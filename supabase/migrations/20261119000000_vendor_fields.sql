-- Custom sections and fields for the vendor editor (see risk-sections.js), kept apart from the
-- risk register's. The shape and checks match risk_sections. Admins and owners change it.
alter table public.organizations add column vendor_sections jsonb
  check (vendor_sections is null or (jsonb_typeof(vendor_sections) = 'array'
    and jsonb_array_length(vendor_sections) <= 20 and pg_column_size(vendor_sections) <= 65536));

create or replace function public.set_org_vendor_sections(org uuid, sections jsonb)
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
  update public.organizations set vendor_sections = sections where id = org;
end $$;

revoke all on function public.set_org_vendor_sections(uuid, jsonb) from public, anon;
grant execute on function public.set_org_vendor_sections(uuid, jsonb) to authenticated;
