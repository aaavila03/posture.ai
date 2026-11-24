-- The workspace's risk appetite (see appetite.js): { "default": "Medium", "categories": { "Data Breach": "Low" } }.
-- default is the highest residual risk level the organisation accepts (Low, Medium, High or Critical) and each
-- category may have its own limit. Null means no appetite is set, and nothing is flagged. Members read the
-- column through org_select; admins and owners change it.
alter table public.organizations add column risk_appetite jsonb
  check (risk_appetite is null or (jsonb_typeof(risk_appetite) = 'object' and pg_column_size(risk_appetite) <= 4096));

create or replace function public.set_org_risk_appetite(org uuid, appetite jsonb)
returns void language plpgsql security definer set search_path = '' as $$
begin
  perform private.require_role(org, 'admin');
  -- A null (SQL or JSON) clears the appetite.
  if appetite is null or appetite = 'null'::jsonb then
    update public.organizations set risk_appetite = null where id = org;
    return;
  end if;
  if jsonb_typeof(appetite) <> 'object' or coalesce(appetite ->> 'default', '') not in ('Low', 'Medium', 'High', 'Critical') then
    raise exception 'the appetite needs a default level of Low, Medium, High or Critical';
  end if;
  if appetite ? 'categories' then
    if jsonb_typeof(appetite -> 'categories') <> 'object' then
      raise exception 'category limits must be an object';
    end if;
    if (select count(*) from jsonb_object_keys(appetite -> 'categories')) > 30 then
      raise exception 'too many category limits';
    end if;
    if exists (select 1 from jsonb_each(appetite -> 'categories') c
      where char_length(c.key) not between 1 and 60 or jsonb_typeof(c.value) <> 'string'
        or (c.value #>> '{}') not in ('Low', 'Medium', 'High', 'Critical')) then
      raise exception 'each category limit must be Low, Medium, High or Critical';
    end if;
  end if;
  update public.organizations set risk_appetite = appetite where id = org;
end $$;

revoke all on function public.set_org_risk_appetite(uuid, jsonb) from public, anon;
grant execute on function public.set_org_risk_appetite(uuid, jsonb) to authenticated;
