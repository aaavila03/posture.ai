-- The custom sections of the risk register editor (see risk-sections.js): each is an id and a
-- name, after the built-in sections. Null means the default list (Other). Members read the
-- column through org_select; admins and owners change it.
alter table public.organizations add column risk_sections jsonb
  check (risk_sections is null or (jsonb_typeof(risk_sections) = 'array'
    and jsonb_array_length(risk_sections) <= 20 and pg_column_size(risk_sections) <= 8192));

create or replace function public.set_org_risk_sections(org uuid, sections jsonb)
returns void language plpgsql security definer set search_path = '' as $$
begin
  perform private.require_role(org, 'admin');
  if sections is null or jsonb_typeof(sections) <> 'array' then raise exception 'sections must be a list'; end if;
  if exists (select 1 from jsonb_array_elements(sections) s
    where jsonb_typeof(s) <> 'object' or coalesce(s ->> 'id', '') !~ '^[a-z0-9]{1,20}$'
      or char_length(btrim(coalesce(s ->> 'name', ''))) not between 1 and 60) then
    raise exception 'each section needs an id and a name';
  end if;
  update public.organizations set risk_sections = sections where id = org;
end $$;

revoke all on function public.set_org_risk_sections(uuid, jsonb) from public, anon;
grant execute on function public.set_org_risk_sections(uuid, jsonb) to authenticated;
