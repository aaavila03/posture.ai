-- Lets an owner delete their whole workspace: its records (risks, vendors, assessments, threat posture assessments),
-- the people directory, saved briefing and settings, members, invitations, and the questionnaire links and responses.
-- All of these are removed by the foreign keys that cascade from organizations. People's sign-in accounts are not
-- deleted. The audit log is not tied to the workspace, so it is kept: the deletions it records stay, and a final
-- entry says who deleted the workspace and when.
--
-- Owners only (on an MFA session), and the caller must pass the workspace's exact name as a second check on top of
-- the confirmation the app asks for.
create or replace function public.delete_workspace(org uuid, confirm_name text)
returns void language plpgsql security definer set search_path = '' as $$
declare
  workspace_name text;
begin
  perform private.require_role(org, 'owner');
  select o.name into workspace_name from public.organizations o where o.id = org;
  if workspace_name is null then raise exception 'workspace not found'; end if;
  if confirm_name is distinct from workspace_name then
    raise exception 'type the workspace name exactly to confirm';
  end if;
  perform private.write_audit(org, 'delete', 'organizations', org::text, jsonb_build_object('name', workspace_name));
  delete from public.organizations where id = org;
end $$;

revoke all on function public.delete_workspace(uuid, text) from public, anon;
grant execute on function public.delete_workspace(uuid, text) to authenticated;
