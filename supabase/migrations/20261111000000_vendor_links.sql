-- Vendor questionnaire links now work like threat risk assessment links. Each vendor has at
-- most one live link, which lasts 14 days and ends when the questionnaire is submitted. An
-- analyst can turn it off or replace it. Answers the requester already holds are shown only if
-- the analyst chooses. Removing a vendor removes its link, response and documents, because
-- vendor IDs can be reused. Earlier links never expired early and couldn't be turned off, so
-- they all stop working now.

delete from public.intake_invites;
drop function public.create_intake_invite(uuid, text);

alter table public.intake_invites add column share_existing boolean not null default false;
alter table public.intake_invites alter column expires_at set default now() + interval '14 days';
alter table public.intake_invites alter column vendor_ref drop default;
alter table public.intake_invites drop constraint intake_invites_vendor_ref_check;
alter table public.intake_invites add constraint intake_invites_vendor_ref_check check (vendor_ref ~ '^V-[0-9]{3,6}$');
alter table public.intake_invites add constraint intake_invites_one_per_vendor unique (org_id, vendor_ref);

create or replace function private.require_vendor(org uuid, ref text)
returns void language plpgsql stable security definer set search_path = '' as $$
begin
  if not exists (select 1 from public.vendors v where v.org_id = org and v.display_id = ref) then raise exception 'vendor not found'; end if;
end $$;

-- Creates or replaces a vendor's link and returns the token (shown only once).
create or replace function public.create_vendor_link(org uuid, ref text, share boolean default false)
returns text language plpgsql security definer set search_path = '' as $$
declare token text := replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', '');
begin
  perform private.require_role(org, 'analyst');
  perform private.require_vendor(org, ref);
  insert into public.intake_invites (org_id, vendor_ref, token_hash, share_existing)
  values (org, ref, encode(sha256(convert_to(token, 'UTF8')), 'hex'), coalesce(share, false))
  on conflict (org_id, vendor_ref) do update set token_hash = excluded.token_hash, share_existing = excluded.share_existing,
    created_by = auth.uid(), created_at = now(), expires_at = now() + interval '14 days', ai_uses = 0;
  perform private.write_audit(org, 'insert', 'intake_invites', ref, jsonb_build_object('share_existing', coalesce(share, false)));
  return token;
end $$;

create or replace function public.revoke_vendor_link(org uuid, ref text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  perform private.require_role(org, 'analyst');
  delete from public.intake_invites i where i.org_id = org and i.vendor_ref = ref;
  perform private.write_audit(org, 'delete', 'intake_invites', ref, null);
end $$;

create or replace function public.get_vendor_link(org uuid, ref text)
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare link public.intake_invites;
begin
  perform private.require_role(org, 'analyst');
  select i.* into link from public.intake_invites i where i.org_id = org and i.vendor_ref = ref and i.expires_at > now();
  return jsonb_build_object('expiresAt', link.expires_at, 'shareExisting', link.share_existing);
end $$;

create or replace function private.clear_vendor_outside()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  delete from public.intake_invites i where i.org_id = old.org_id and i.vendor_ref = old.display_id;
  delete from public.intake_responses r where r.org_id = old.org_id and r.vendor_ref = old.display_id;
  delete from public.intake_documents d where d.org_id = old.org_id and d.vendor_ref = old.display_id;
  return old;
end $$;
create trigger vendors_clear_outside after delete on public.vendors for each row execute function private.clear_vendor_outside();

revoke all on function private.require_vendor(uuid, text), private.clear_vendor_outside(),
  public.create_vendor_link(uuid, text, boolean), public.revoke_vendor_link(uuid, text), public.get_vendor_link(uuid, text) from public, anon, authenticated;
grant execute on function public.create_vendor_link(uuid, text, boolean), public.revoke_vendor_link(uuid, text), public.get_vendor_link(uuid, text) to authenticated;
