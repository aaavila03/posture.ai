-- The organisation's own logo, shown in the app, on exports and on vendor questionnaires.
-- Stored as a small image data URL (the browser resizes uploads before saving).
alter table public.organizations add column logo text
  check (logo is null or (char_length(logo) <= 300000
    and logo ~ '^data:image/(png|jpeg|webp|svg\+xml);base64,[A-Za-z0-9+/]+={0,2}$'));

-- Admins and owners set or clear it (null removes it). Members read it through org_select.
create or replace function public.set_org_logo(org uuid, logo text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  perform private.require_role(org, 'admin');
  update public.organizations set logo = nullif(btrim(set_org_logo.logo), '') where id = org;
end $$;

revoke all on function public.set_org_logo(uuid, text) from public, anon;
grant execute on function public.set_org_logo(uuid, text) to authenticated;
