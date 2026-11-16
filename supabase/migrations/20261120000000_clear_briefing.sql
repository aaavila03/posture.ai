-- Delete all data (Settings) also removes the saved executive briefing. Admins and owners only.
create or replace function public.clear_briefing(org uuid)
returns void language plpgsql security definer set search_path = '' as $$
begin
  perform private.require_role(org, 'admin');
  delete from public.briefings where org_id = org;
end $$;

revoke all on function public.clear_briefing(uuid) from public, anon;
grant execute on function public.clear_briefing(uuid) to authenticated;
