-- The company's internal standards (see standards.js): a list of short names loaded from files
-- and offered as the Internal standard dropdown on risks. Null or empty means none loaded.
-- Members read the column through org_select; admins and owners change it.
alter table public.organizations add column internal_standards jsonb
  check (internal_standards is null or (jsonb_typeof(internal_standards) = 'array'
    and jsonb_array_length(internal_standards) <= 500 and pg_column_size(internal_standards) <= 65536));

create or replace function public.set_org_internal_standards(org uuid, standards jsonb)
returns void language plpgsql security definer set search_path = '' as $$
begin
  perform private.require_role(org, 'admin');
  if standards is null or jsonb_typeof(standards) <> 'array' then raise exception 'standards must be a list'; end if;
  if exists (select 1 from jsonb_array_elements(standards) s
    where jsonb_typeof(s) <> 'string' or char_length(btrim(s #>> '{}')) not between 1 and 200) then
    raise exception 'each standard needs a name of 1 to 200 characters';
  end if;
  update public.organizations set internal_standards = standards where id = org;
end $$;

revoke all on function public.set_org_internal_standards(uuid, jsonb) from public, anon;
grant execute on function public.set_org_internal_standards(uuid, jsonb) to authenticated;
