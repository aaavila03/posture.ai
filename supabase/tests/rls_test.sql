-- Security tests for the Posture.ai schema. Run with: supabase/tests/run.sh
\set ON_ERROR_STOP on
\set QUIET on

create schema test;
grant usage on schema test to anon, authenticated;
create table test.results (name text, ok boolean, detail text);
grant insert, select on test.results to anon, authenticated;

-- Switches the simulated JWT (role is switched separately with SET ROLE).
create function test.login(uid uuid, aal text default 'aal2', email text default null) returns void language sql as $$
  select set_config('request.jwt.claims', json_build_object('sub', uid, 'aal', aal, 'email', email, 'role', 'authenticated')::text, false)
$$;
create function test.ok(name text, cond boolean, detail text default null) returns void language sql as $$
  insert into test.results values (name, coalesce(cond, false), detail)
$$;
-- Passes if the statement raises an error.
create function test.fails(name text, stmt text) returns void language plpgsql as $$
begin
  begin
    execute stmt;
  exception when others then
    perform test.ok(name, true, sqlerrm);
    return;
  end;
  perform test.ok(name, false, 'statement succeeded');
end $$;
create function test.count(stmt text) returns bigint language plpgsql as $$
declare n bigint;
begin execute 'select count(*) from (' || stmt || ') s' into n; return n; end $$;
-- Rows changed by an UPDATE or DELETE.
create function test.affected(stmt text) returns bigint language plpgsql as $$
declare n bigint;
begin execute stmt; get diagnostics n = row_count; return n; end $$;
grant execute on all functions in schema test to anon, authenticated;

insert into auth.users values
  ('00000000-0000-0000-0000-00000000000a', 'alice@acme.test', now()),
  ('00000000-0000-0000-0000-00000000000b', 'bob@other.test', now()),
  ('00000000-0000-0000-0000-00000000000c', 'carol@acme.test', now()),
  ('00000000-0000-0000-0000-00000000000d', 'dave@acme.test', now()),
  ('00000000-0000-0000-0000-00000000000e', 'erin@acme.test', null);

\set alice '\'00000000-0000-0000-0000-00000000000a\''
\set bob '\'00000000-0000-0000-0000-00000000000b\''
\set carol '\'00000000-0000-0000-0000-00000000000c\''
\set dave '\'00000000-0000-0000-0000-00000000000d\''
\set erin '\'00000000-0000-0000-0000-00000000000e\''

-- ---- MFA required ----
select test.login(:alice, 'aal1', 'alice@acme.test');
set role authenticated;
select test.fails('aal1 cannot create an organisation', $$select public.create_organization('Acme', 'csf2')$$);
reset role;

-- ---- Alice creates Acme; Bob creates Other ----
select test.login(:alice, 'aal2', 'alice@acme.test');
set role authenticated;
select public.create_organization('Acme', 'csf2') as acme \gset
select test.ok('a new workspace keeps its chosen framework', (select tra_framework from public.organizations where id = :'acme') = 'csf2');
select test.fails('a workspace needs a known framework', $$select public.create_organization('Nope', 'iso27001')$$);
select test.fails('a workspace needs a framework', $$select public.create_organization('Nope', null)$$);
select test.ok('creator is owner', (select role from public.my_organizations() where org_id = :'acme') = 'owner');
insert into public.risks (org_id, display_id, data) values (:'acme', 'R-001', '{"title":"VPN"}');
select test.ok('owner can add a risk', test.count($$select 1 from public.risks$$) = 1);
insert into public.vendors (org_id, display_id, data) values (:'acme', 'V-001', '{"name":"NetOps"}');
reset role;

select test.login(:bob, 'aal2', 'bob@other.test');
set role authenticated;
select public.create_organization('Other', 'sp80053') as other \gset
select test.ok('tenant isolation: Bob sees no Acme risks', test.count($$select 1 from public.risks$$) = 0);
select test.ok('tenant isolation: Bob sees no Acme vendors', test.count($$select 1 from public.vendors$$) = 0);
select test.ok('tenant isolation: Bob sees only his organisation', test.count($$select 1 from public.organizations$$) = 1);
select test.ok('tenant isolation: Bob sees no Acme memberships', test.count(format($$select 1 from public.memberships where org_id = %L$$, :'acme')) = 0);
select test.fails('tenant isolation: Bob cannot insert into Acme', format($$insert into public.risks (org_id, display_id, data) values (%L, 'R-002', '{}')$$, :'acme'));
select test.ok('tenant isolation: Bob cannot update Acme risks', test.affected(format($$update public.risks set data = '{"title":"pwned"}' where org_id = %L$$, :'acme')) = 0);
select test.ok('tenant isolation: Bob cannot delete Acme risks', test.affected(format($$delete from public.risks where org_id = %L$$, :'acme')) = 0);
select test.fails('tenant isolation: Bob cannot invite into Acme', format($$select public.invite_member(%L, 'x@x.test', 'viewer')$$, :'acme'));
select test.fails('tenant isolation: Bob cannot read Acme quota', format($$select 1/(select count(*) from public.ai_quota(%L))::int$$, :'acme'));
reset role;

-- ---- aal1 session sees nothing even as owner ----
select test.login(:alice, 'aal1', 'alice@acme.test');
set role authenticated;
select test.ok('aal1 owner sees no risks', test.count($$select 1 from public.risks$$) = 0);
select test.fails('aal1 owner cannot insert', format($$insert into public.risks (org_id, display_id, data) values (%L, 'R-009', '{}')$$, :'acme'));
reset role;

-- ---- anonymous has no access ----
select set_config('request.jwt.claims', '{}', false);
set role anon;
select test.fails('anon cannot read risks', $$select * from public.risks$$);
select test.fails('anon cannot call create_organization', $$select public.create_organization('x', 'csf2')$$);
reset role;

-- ---- invitations and roles ----
select test.login(:alice, 'aal2', 'alice@acme.test');
set role authenticated;
select public.invite_member(:'acme', 'Carol@Acme.test', 'analyst') as carol_invite \gset
select public.set_invitation_profile(:'carol_invite', '{"first_name":"Carol","last_name":"Ng","title":"Risk Analyst","department":"IT GRC","phone":"+1 555 0100"}');
select public.invite_member(:'acme', 'dave@acme.test', 'viewer');
select public.invite_member(:'acme', 'erin@acme.test', 'viewer');
select test.fails('cannot invite as owner', format($$select public.invite_member(%L, 'z@z.test', 'owner')$$, :'acme'));
reset role;

select test.login(:carol, 'aal1', 'carol@acme.test');
set role authenticated;
select test.fails('accepting invitations requires MFA', $$select public.accept_invitations()$$);
reset role;
select test.login(:carol, 'aal2', 'carol@acme.test');
set role authenticated;
select test.ok('carol accepts invitation', public.accept_invitations() = 1);
select test.ok('carol is analyst', (select role from public.my_organizations() where org_id = :'acme') = 'analyst');
select test.ok('invitation details become the new member''s profile',
  (select first_name || ' ' || last_name || ' / ' || title || ' / ' || department from public.profiles where user_id = :carol::uuid) = 'Carol Ng / Risk Analyst / IT GRC');
select test.fails('analyst cannot attach invitation details', format($$select public.set_invitation_profile(%L, '{}')$$, :'carol_invite'));
select test.fails('created_by cannot be set by clients', format($$insert into public.risks (org_id, display_id, data, created_by) values (%L, 'R-002', '{}', %L)$$, :'acme', :bob));
insert into public.risks (org_id, display_id, data) values (:'acme', 'R-002', '{"title":"Phishing"}');
select test.ok('created_by is stamped by the server', (select created_by from public.risks where display_id = 'R-002') = :carol::uuid);
update public.risks set data = '{"title":"Phishing v2","owner":"CFO"}' where display_id = 'R-002';
select test.fails('analyst cannot update created_by column', $$update public.risks set created_by = gen_random_uuid()$$);
select test.fails('records cannot move organisation', format($$update public.risks set org_id = %L where display_id = 'R-002'$$, :'other'));
select test.ok('analyst cannot read audit log', test.count($$select 1 from public.audit_log$$) = 0);
select test.ok('analyst cannot see invitations', test.count($$select 1 from public.invitations$$) = 0);
select test.fails('analyst cannot invite', format($$select public.invite_member(%L, 'q@q.test', 'viewer')$$, :'acme'));
select test.fails('analyst cannot change roles', format($$select public.set_member_role(%L, %L, 'admin')$$, :'acme', :carol));
select test.fails('analyst cannot set the internal standards', format($$select public.set_org_internal_standards(%L, '["ISO 27001"]'::jsonb)$$, :'acme'));
select test.fails('analyst cannot set the risk appetite', format($$select public.set_org_risk_appetite(%L, '{"default":"Medium"}'::jsonb)$$, :'acme'));
select test.fails('display_id format enforced', format($$insert into public.risks (org_id, display_id, data) values (%L, 'R-1; drop', '{}')$$, :'acme'));
select test.fails('data must be an object', format($$insert into public.risks (org_id, display_id, data) values (%L, 'R-003', '[1,2]')$$, :'acme'));
select test.fails('data size limited', format($$insert into public.risks (org_id, display_id, data) values (%L, 'R-004', jsonb_build_object('x', repeat(md5(random()::text), 5000)))$$, :'acme'));
select test.fails('duplicate display_id rejected', format($$insert into public.risks (org_id, display_id, data) values (%L, 'R-001', '{}')$$, :'acme'));
delete from public.risks where display_id = 'R-002';
select test.ok('analyst can delete', test.count($$select 1 from public.risks where display_id = 'R-002'$$) = 0);
reset role;

select test.login(:dave, 'aal2', 'dave@acme.test');
set role authenticated;
select public.accept_invitations();
select test.ok('viewer can read risks', test.count($$select 1 from public.risks$$) = 1);
select test.fails('viewer cannot insert', format($$insert into public.risks (org_id, display_id, data) values (%L, 'R-005', '{}')$$, :'acme'));
select test.ok('viewer cannot update', test.affected($$update public.risks set data = '{}'$$) = 0);
select test.ok('viewer cannot delete', test.affected($$delete from public.risks$$) = 0);
select test.ok('a viewer can read a risk''s history',
  (select string_agg(action || ' by ' || actor_email, ',') from public.risk_history(:'acme', 'R-001')) = 'insert by alice@acme.test',
  (select coalesce(string_agg(action || ' ' || coalesce(actor_email, 'null'), ' | '), 'no rows') from public.risk_history(:'acme', 'R-001')));
select test.ok('viewer rename has no effect', test.affected(format($$update public.organizations set name = 'Hacked' where id = %L$$, :'acme')) = 0);
select test.fails('viewer cannot raise AI limit', format($$update public.organizations set ai_monthly_limit = 99999 where id = %L$$, :'acme'));
reset role;

-- ---- vendor links ----
select test.login(:carol, 'aal2', 'carol@acme.test');
set role authenticated;
select public.create_vendor_link(:'acme', 'V-001') as invite_token \gset
select test.ok('analyst can create a vendor link', length(:'invite_token') = 64);
select test.fails('a link needs a real vendor', format($$select public.create_vendor_link(%L, 'V-999')$$, :'acme'));
select test.fails('invites are not readable through the API', $$select 1 from public.intake_invites$$);
select test.fails('no direct invite writes', format($$insert into public.intake_invites (org_id, vendor_ref, token_hash) values (%L, 'V-001', repeat('a', 64))$$, :'acme'));
select test.ok('a vendor link shows as active', public.get_vendor_link(:'acme', 'V-001') ->> 'expiresAt' is not null);
select test.ok('a vendor link hides answers on file by default', public.get_vendor_link(:'acme', 'V-001') -> 'shareExisting' = 'false'::jsonb);
reset role;
select test.ok('only the token hash is stored',
  (select token_hash from public.intake_invites) = encode(sha256(convert_to(:'invite_token', 'UTF8')), 'hex')
  and not exists (select 1 from public.intake_invites where token_hash = :'invite_token'));
select test.ok('vendor links last 14 days with 5 AI runs',
  (select expires_at between now() + interval '13 days' and now() + interval '14 days 1 minute' and ai_limit = 5 and created_by = :carol::uuid from public.intake_invites));
select test.fails('a link must name a vendor', format($$insert into public.intake_invites (org_id, vendor_ref, token_hash) values (%L, '', repeat('b', 64))$$, :'acme'));
update public.intake_invites set ai_uses = 3;

select test.login(:carol, 'aal2', 'carol@acme.test');
set role authenticated;
select public.create_vendor_link(:'acme', 'V-001', true) as invite_token_2 \gset
select test.ok('a vendor link can show answers on file when chosen', public.get_vendor_link(:'acme', 'V-001') -> 'shareExisting' = 'true'::jsonb);
reset role;
select test.ok('a vendor has one link, and a new one replaces the old', (select count(*) from public.intake_invites) = 1
  and (select token_hash from public.intake_invites) = encode(sha256(convert_to(:'invite_token_2', 'UTF8')), 'hex'));
select test.ok('a new vendor link starts with its own AI runs', (select ai_uses from public.intake_invites) = 0);

select test.login(:carol, 'aal2', 'carol@acme.test');
set role authenticated;
select public.revoke_vendor_link(:'acme', 'V-001');
select test.ok('a vendor link can be turned off', public.get_vendor_link(:'acme', 'V-001') ->> 'expiresAt' is null);
select public.create_vendor_link(:'acme', 'V-001') as invite_token_3 \gset
reset role;
update public.intake_invites set expires_at = now() - interval '1 minute';
select test.login(:carol, 'aal2', 'carol@acme.test');
set role authenticated;
select test.ok('an expired vendor link shows as inactive', public.get_vendor_link(:'acme', 'V-001') ->> 'expiresAt' is null);
select public.revoke_vendor_link(:'acme', 'V-001');
reset role;

select test.login(:dave, 'aal2', 'dave@acme.test');
set role authenticated;
select test.fails('viewer cannot create a vendor link', format($$select public.create_vendor_link(%L, 'V-001')$$, :'acme'));
select test.fails('viewer cannot turn off a vendor link', format($$select public.revoke_vendor_link(%L, 'V-001')$$, :'acme'));
select test.fails('viewer cannot read a vendor link', format($$select public.get_vendor_link(%L, 'V-001')$$, :'acme'));
reset role;

select test.login(:bob, 'aal2', 'bob@other.test');
set role authenticated;
select test.fails('tenant isolation: Bob cannot create Acme vendor links', format($$select public.create_vendor_link(%L, 'V-001')$$, :'acme'));
select test.fails('tenant isolation: Bob cannot turn off Acme vendor links', format($$select public.revoke_vendor_link(%L, 'V-001')$$, :'acme'));
reset role;

select test.login(:carol, 'aal1', 'carol@acme.test');
set role authenticated;
select test.fails('aal1 cannot create a vendor link', format($$select public.create_vendor_link(%L, 'V-001')$$, :'acme'));
reset role;

select set_config('request.jwt.claims', '{}', false);
set role anon;
select test.fails('no outside vendor link creation', format($$select public.create_vendor_link(%L, 'V-001')$$, :'acme'));
select test.fails('no outside vendor link status', format($$select public.get_vendor_link(%L, 'V-001')$$, :'acme'));
reset role;

-- Removing a vendor removes its link, answers and documents, so a reused ID can't inherit them.
select test.login(:carol, 'aal2', 'carol@acme.test');
set role authenticated;
insert into public.vendors (org_id, display_id, data) values (:'acme', 'V-077', '{"name":"Short-lived"}');
select public.create_vendor_link(:'acme', 'V-077');
reset role;
insert into public.intake_responses (org_id, vendor_ref, response) values (:'acme', 'V-077', '{"answers":{}}');
insert into public.intake_documents (org_id, vendor_ref, name, media_type, size, data) values (:'acme', 'V-077', 'a.txt', 'text/plain', 3, 'YWJj');
select test.login(:carol, 'aal2', 'carol@acme.test');
set role authenticated;
delete from public.vendors where display_id = 'V-077';
reset role;
select test.ok('removing a vendor removes its link, answers and documents',
  not exists (select 1 from public.intake_invites where vendor_ref = 'V-077') and not exists (select 1 from public.intake_responses where vendor_ref = 'V-077')
  and not exists (select 1 from public.intake_documents where vendor_ref = 'V-077'));

-- ---- vendor responses and documents (written by the intake-ai function, as the table owner) ----
insert into public.intake_responses (org_id, vendor_ref, response, status) values (:'acme', 'V-001', '{"answers":{}}', 'submitted');
insert into public.intake_documents (org_id, vendor_ref, name, media_type, size, data) values (:'acme', 'V-001', 'soc2.pdf', 'application/pdf', 3, 'YWJj');
select test.fails('response vendor ref format enforced', format($$insert into public.intake_responses (org_id, vendor_ref, response) values (%L, 'x', '{}')$$, :'acme'));
select test.fails('document type restricted', format($$insert into public.intake_documents (org_id, vendor_ref, name, media_type, size, data) values (%L, 'V-001', 'x.exe', 'application/x-msdownload', 1, 'a')$$, :'acme'));

select test.login(:dave, 'aal2', 'dave@acme.test');
set role authenticated;
select test.ok('viewers cannot read vendors', test.count($$select 1 from public.vendors$$) = 0);
select test.ok('viewers cannot read vendor responses', test.count($$select 1 from public.intake_responses$$) = 0);
select test.ok('viewers cannot read vendor documents', test.count($$select 1 from public.intake_documents$$) = 0);
select test.ok('viewers can still read risks', test.count($$select 1 from public.risks$$) > 0);
select test.fails('no direct response writes', format($$insert into public.intake_responses (org_id, vendor_ref, response) values (%L, 'V-002', '{}')$$, :'acme'));
select test.fails('no response updates', $$update public.intake_responses set status = 'draft'$$);
select test.fails('no document deletes', $$delete from public.intake_documents$$);
reset role;

select test.login(:bob, 'aal2', 'bob@other.test');
set role authenticated;
select test.ok('tenant isolation: Bob sees no Acme vendor responses', test.count($$select 1 from public.intake_responses$$) = 0);
select test.ok('tenant isolation: Bob sees no Acme vendor documents', test.count($$select 1 from public.intake_documents$$) = 0);
reset role;

select test.login(:dave, 'aal1', 'dave@acme.test');
set role authenticated;
select test.ok('aal1 sees no vendor responses', test.count($$select 1 from public.intake_responses$$) = 0);
reset role;

-- ---- member profiles ----
select test.login(:dave, 'aal2', 'dave@acme.test');
set role authenticated;
select public.save_profile(:'acme', :dave, 'Dave', 'Lee', 'Auditor', '(555) 010-2000 x12', 'Internal Audit');
select test.ok('members can save their own profile', (select title from public.profiles where user_id = :dave::uuid) = 'Auditor');
select test.ok('members can read co-members'' profiles', test.count($$select 1 from public.profiles$$) >= 2);
select test.fails('members cannot edit someone else''s profile', format($$select public.save_profile(%L, %L, 'x', 'x', 'x', '', 'x')$$, :'acme', :carol));
select test.fails('phone format enforced', format($$select public.save_profile(%L, %L, 'Dave', 'Lee', '', 'call me; drop', '')$$, :'acme', :dave));
select test.fails('no direct profile writes', format($$insert into public.profiles (user_id) values (%L)$$, :dave));
select test.fails('no direct profile updates', $$update public.profiles set title = 'CEO'$$);
reset role;

select test.login(:alice, 'aal2', 'alice@acme.test');
set role authenticated;
select public.save_profile(:'acme', :dave, 'Dave', 'Lee', 'Senior Auditor', '', 'Internal Audit');
select test.ok('admins can edit their members'' profiles', (select title from public.profiles where user_id = :dave::uuid) = 'Senior Auditor');
select test.fails('cannot edit a profile through a workspace they are not in', format($$select public.save_profile(%L, %L, 'x', '', '', '', '')$$, :'acme', :bob));
reset role;

select test.login(:bob, 'aal2', 'bob@other.test');
set role authenticated;
select test.ok('tenant isolation: Bob sees only his own profile row', test.count($$select 1 from public.profiles where user_id <> '00000000-0000-0000-0000-00000000000b'$$) = 0);
reset role;
select test.login(:dave, 'aal1', 'dave@acme.test');
set role authenticated;
select test.ok('aal1 sees no other profiles', test.count($$select 1 from public.profiles where user_id <> '00000000-0000-0000-0000-00000000000d'$$) = 0);
reset role;

-- ---- people directory ----
select test.login(:alice, 'aal2', 'alice@acme.test');
set role authenticated;
select test.ok('admins import the hierarchy', public.import_people(:'acme', $$[
  {"email": "Vp@Acme.test", "first_name": "Val", "last_name": "Park", "title": "VP Technology"},
  {"email": "dir@acme.test", "first_name": "Dee", "last_name": "Ray", "title": "Director IT", "manager_email": "vp@acme.test"},
  {"email": "eng@acme.test", "first_name": "Eli", "last_name": "Ng", "department": "IT", "manager_email": "DIR@acme.test"},
  {"email": "", "first_name": "No email"}]$$) = 3);
select test.ok('emails are stored lower-case', (select manager_email from public.people where email = 'eng@acme.test') = 'dir@acme.test');
select test.ok('re-importing keeps everyone else', public.import_people(:'acme', $$[{"email": "eng@acme.test", "first_name": "Eli", "last_name": "Ng", "title": "Engineer", "manager_email": "dir@acme.test"}]$$) = 3);
select test.ok('re-importing updates people', (select title from public.people where email = 'eng@acme.test') = 'Engineer');
select test.ok('replace removes people not in the file', public.import_people(:'acme', $$[{"email": "vp@acme.test", "first_name": "Val"}, {"email": "dir@acme.test", "first_name": "Dee", "manager_email": "vp@acme.test"}]$$, true) = 2);
select test.fails('a person needs a name', format($$select public.import_people(%L, '[{"email": "x@acme.test"}]')$$, :'acme'));
select test.fails('phone format enforced in the directory', format($$select public.import_people(%L, '[{"email": "x@acme.test", "first_name": "X", "phone": "drop table"}]')$$, :'acme'));
select public.save_person(:'acme', '{"email": "Eng@acme.test", "first_name": "Eli", "last_name": "Ng", "manager_email": "dir@acme.test"}');
select test.ok('admins add a person by hand', (select manager_email from public.people where email = 'eng@acme.test') = 'dir@acme.test');
select test.fails('no reporting loops', format($$select public.save_person(%L, '{"email": "vp@acme.test", "first_name": "Val", "manager_email": "eng@acme.test"}')$$, :'acme'));
select test.fails('no reporting to yourself', format($$select public.save_person(%L, '{"email": "eng@acme.test", "first_name": "Eli", "manager_email": "eng@acme.test"}')$$, :'acme'));
select test.fails('the manager must be in the directory', format($$select public.save_person(%L, '{"email": "eng@acme.test", "first_name": "Eli", "manager_email": "ghost@acme.test"}')$$, :'acme'));
select public.save_person(:'acme', '{"email": "director@acme.test", "first_name": "Dee", "manager_email": "vp@acme.test"}', 'dir@acme.test');
select test.ok('changing an email moves their reports with them', (select manager_email from public.people where email = 'eng@acme.test') = 'director@acme.test'
  and not exists (select 1 from public.people where email = 'dir@acme.test'));
select test.fails('cannot take another person''s email', format($$select public.save_person(%L, '{"email": "vp@acme.test", "first_name": "Dee"}', 'director@acme.test')$$, :'acme'));
select public.delete_person(:'acme', 'director@acme.test');
select test.ok('removing a person moves their reports up', (select manager_email from public.people where email = 'eng@acme.test') = 'vp@acme.test');
select public.save_person(:'acme', '{"email": "dir@acme.test", "first_name": "Dee", "manager_email": "vp@acme.test"}');
select public.delete_person(:'acme', 'eng@acme.test');
select test.fails('no direct directory writes', format($$insert into public.people (org_id, email, first_name) values (%L, 'z@acme.test', 'Z')$$, :'acme'));
reset role;

select test.login(:dave, 'aal2', 'dave@acme.test');
set role authenticated;
select test.ok('viewers can read the directory', test.count($$select 1 from public.people$$) = 2);
select test.fails('viewers cannot import people', format($$select public.import_people(%L, '[{"email": "x@acme.test", "first_name": "X"}]')$$, :'acme'));
select test.fails('viewers cannot add people', format($$select public.save_person(%L, '{"email": "x@acme.test", "first_name": "X"}')$$, :'acme'));
select test.fails('viewers cannot remove people', format($$select public.delete_person(%L, 'vp@acme.test')$$, :'acme'));
select test.fails('viewers cannot clear the directory', format($$select public.clear_people(%L)$$, :'acme'));
select test.fails('no direct directory deletes', $$delete from public.people$$);
reset role;

select test.login(:carol, 'aal2', 'carol@acme.test');
set role authenticated;
select test.fails('analysts cannot import people', format($$select public.import_people(%L, '[{"email": "x@acme.test", "first_name": "X"}]')$$, :'acme'));
reset role;

select test.login(:bob, 'aal2', 'bob@other.test');
set role authenticated;
select test.ok('tenant isolation: Bob cannot see Acme''s directory', test.count($$select 1 from public.people$$) = 0);
select test.fails('Bob cannot remove Acme''s people', format($$select public.delete_person(%L, 'vp@acme.test')$$, :'acme'));
select test.fails('Bob cannot import into Acme', format($$select public.import_people(%L, '[{"email": "x@acme.test", "first_name": "X"}]')$$, :'acme'));
reset role;

select test.login(:dave, 'aal1', 'dave@acme.test');
set role authenticated;
select test.ok('aal1 cannot read the directory', test.count($$select 1 from public.people$$) = 0);
reset role;

-- ---- ad-hoc risk assessments ----
select test.login(:carol, 'aal2', 'carol@acme.test');
set role authenticated;
insert into public.assessments (org_id, display_id, data) values (:'acme', 'A-001', '{"solution":"ChatGPT Enterprise"}');
select test.ok('analysts add assessments', test.count($$select 1 from public.assessments$$) = 1);
select test.ok('assessment authorship stamped', (select created_by from public.assessments where display_id = 'A-001') = :carol::uuid);
update public.assessments set data = '{"solution":"ChatGPT Enterprise","outcome":"No objection"}' where display_id = 'A-001';
select test.fails('assessment id format enforced', format($$insert into public.assessments (org_id, display_id, data) values (%L, 'R-001', '{}')$$, :'acme'));
select test.fails('assessment data must be an object', format($$insert into public.assessments (org_id, display_id, data) values (%L, 'A-002', '[1]')$$, :'acme'));
reset role;

select test.login(:dave, 'aal2', 'dave@acme.test');
set role authenticated;
select test.ok('viewers read assessments', test.count($$select 1 from public.assessments$$) = 1);
select test.fails('viewers cannot add assessments', format($$insert into public.assessments (org_id, display_id, data) values (%L, 'A-009', '{}')$$, :'acme'));
select test.ok('viewers cannot edit assessments', test.affected($$update public.assessments set data = '{}'$$) = 0);
select test.ok('viewers cannot delete assessments', test.affected($$delete from public.assessments$$) = 0);
reset role;

select test.login(:bob, 'aal2', 'bob@other.test');
set role authenticated;
select test.ok('tenant isolation: Bob sees no Acme assessments', test.count($$select 1 from public.assessments$$) = 0);
select test.fails('Bob cannot add to Acme', format($$insert into public.assessments (org_id, display_id, data) values (%L, 'A-010', '{}')$$, :'acme'));
reset role;

-- Intake questionnaire links for someone in the business without an account.
select test.login(:carol, 'aal2', 'carol@acme.test');
set role authenticated;
insert into public.assessments (org_id, display_id, data) values (:'acme', 'A-020',
  '{"solution":"Archive utility","status":"Draft","intakeTypes":["software","ai"],"riskOwner":"secret-owner","summaryComments":"secret-summary","recommendations":[{"recommendation":"secret-rec"}]}');
select public.create_assessment_intake_link(:'acme', 'A-020') as intake_token \gset
select test.ok('intake tokens are long and random', length(:'intake_token') = 64);
select test.fails('an intake link needs an existing assessment', format($$select public.create_assessment_intake_link(%L, 'A-999')$$, :'acme'));
reset role;
select test.ok('only a hash of the intake token is stored', not exists (select 1 from public.assessment_intake_links where token_hash = :'intake_token'));
select test.ok('new intake links last 14 days', (select expires_at from public.assessment_intake_links where org_id = :'acme') between now() + interval '13 days' and now() + interval '14 days 1 minute');

select test.login(:dave, 'aal2', 'dave@acme.test');
set role authenticated;
select test.fails('viewers cannot create intake links', format($$select public.create_assessment_intake_link(%L, 'A-020')$$, :'acme'));
select test.fails('viewers cannot read intake answers', format($$select public.get_assessment_intake(%L, 'A-020')$$, :'acme'));
select test.fails('viewers cannot turn off intake links', format($$select public.revoke_assessment_intake_link(%L, 'A-020')$$, :'acme'));
select test.fails('members cannot read intake links directly', $$select 1 from public.assessment_intake_links$$);
select test.fails('members cannot read intake answers directly', $$select 1 from public.assessment_intake_responses$$);
reset role;

select test.login(:bob, 'aal2', 'bob@other.test');
set role authenticated;
select test.fails('another workspace cannot create intake links', format($$select public.create_assessment_intake_link(%L, 'A-020')$$, :'acme'));
select test.fails('another workspace cannot read intake answers', format($$select public.get_assessment_intake(%L, 'A-020')$$, :'acme'));
reset role;

select set_config('request.jwt.claims', '{}', false);
set role anon;
select test.ok('an intake link shows the request to someone without an account', public.assessment_intake_load(:'intake_token') ->> 'requestName' = 'Archive utility');
select test.ok('an intake link carries the question sets the analyst chose', public.assessment_intake_load(:'intake_token') -> 'types' = '["software","ai"]'::jsonb);
select test.ok('an intake link returns nothing else from the assessment', public.assessment_intake_load(:'intake_token')::text not like '%secret-%');
select test.fails('a wrong intake token is refused', $$select public.assessment_intake_load(repeat('a', 64))$$);
select test.fails('a malformed intake token is refused', $$select public.assessment_intake_load('x')$$);
select test.fails('no intake token is refused', $$select public.assessment_intake_save(null, '{}')$$);
select test.fails('no outside intake link creation', format($$select public.create_assessment_intake_link(%L, 'A-020')$$, :'acme'));
select test.fails('no outside reading of intake answers', format($$select public.get_assessment_intake(%L, 'A-020')$$, :'acme'));
select public.assessment_intake_save(:'intake_token', '{"contributor":{"name":"Pat Doe","email":"pat@example.test","extra":"x"},"answers":{"RQ1":{"t":"An archive tool"}},"riskOwner":"injected","recommendations":[{"recommendation":"injected"}]}');
select test.fails('an intake link refuses answers to unknown questions', format($$select public.assessment_intake_save(%L, '{"answers":{"not a question":{"t":"x"}}}')$$, :'intake_token'));
select test.fails('an intake link refuses answers with unexpected fields', format($$select public.assessment_intake_save(%L, '{"answers":{"RQ1":{"t":"x","script":"y"}}}')$$, :'intake_token'));
select test.fails('submitting intake answers needs a name', format($$select public.assessment_intake_save(%L, '{"answers":{}}', true)$$, :'intake_token'));
select test.fails('an intake response must be an object', format($$select public.assessment_intake_save(%L, '[1]')$$, :'intake_token'));
select test.fails('oversized intake responses are refused', format($$select public.assessment_intake_save(%L, jsonb_build_object('answers', jsonb_build_object('RQ1', jsonb_build_object('t', (select string_agg(md5(i::text), '') from generate_series(1, 40000) i)))))$$, :'intake_token'));
select test.ok('a saved intake draft comes back with the link', public.assessment_intake_load(:'intake_token') #>> '{response,answers,RQ1,t}' = 'An archive tool');
select test.ok('intake contact details never go back to the form', public.assessment_intake_load(:'intake_token')::text not like '%pat@example%' and public.assessment_intake_load(:'intake_token')::text not like '%Pat Doe%');
reset role;

select test.login(:carol, 'aal2', 'carol@acme.test');
set role authenticated;
select test.ok('analysts see an intake draft in progress', public.get_assessment_intake(:'acme', 'A-020') ->> 'draftBy' = 'Pat Doe' and public.get_assessment_intake(:'acme', 'A-020') ->> 'submittedAt' is null);
select test.ok('an intake draft changes nothing on the assessment', (select data ->> 'riskOwner' from public.assessments where display_id = 'A-020') = 'secret-owner');
reset role;

select set_config('request.jwt.claims', '{}', false);
set role anon;
select test.ok('submitting intake answers works without an account', public.assessment_intake_save(:'intake_token', '{"contributor":{"name":"Pat Doe","email":"alice@acme.test"},"answers":{"RQ1":{"t":"An archive tool"},"DP4":{"a":"Yes"}},"riskOwner":"injected"}', true) ->> 'status' = 'submitted');
select test.fails('submitting ends the intake link', format($$select public.assessment_intake_load(%L)$$, :'intake_token'));
select test.fails('an intake link allows only one submission', format($$select public.assessment_intake_save(%L, '{"contributor":{"name":"Again"}}', true)$$, :'intake_token'));
reset role;
select test.ok('intake submissions are audited as coming from a link', exists (select 1 from public.audit_log where entity = 'assessment_intake_responses' and entity_id = 'A-020' and actor is null and actor_email = 'outside link' and details ->> 'entered_name' = 'Pat Doe'));
select test.ok('only the expected parts of an intake response are kept', (select response from public.assessment_intake_responses where status = 'submitted') = '{"contributor":{"name":"Pat Doe","email":"alice@acme.test"},"answers":{"RQ1":{"t":"An archive tool"},"DP4":{"a":"Yes"}}}'::jsonb);

select test.login(:carol, 'aal2', 'carol@acme.test');
set role authenticated;
select test.ok('analysts read submitted intake answers', public.get_assessment_intake(:'acme', 'A-020') #>> '{response,answers,DP4,a}' = 'Yes' and public.get_assessment_intake(:'acme', 'A-020') ->> 'submittedAt' is not null);
select test.ok('a submitted intake link shows as inactive', public.get_assessment_intake(:'acme', 'A-020') ->> 'expiresAt' is null);
select test.ok('submitted intake answers change nothing on the assessment until applied', (select data from public.assessments where display_id = 'A-020') ->> 'riskOwner' = 'secret-owner' and (select data from public.assessments where display_id = 'A-020') -> 'intake' is null);
select public.create_assessment_intake_link(:'acme', 'A-020') as intake_second \gset
select test.ok('a new intake link cannot see earlier submitted answers', public.assessment_intake_load(:'intake_second') -> 'response' = 'null'::jsonb);
select public.assessment_intake_save(:'intake_second', '{"answers":{"RQ1":{"t":"Second draft"}}}');
select test.ok('a new intake draft does not replace submitted answers', public.get_assessment_intake(:'acme', 'A-020') #>> '{response,answers,RQ1,t}' = 'An archive tool');
select public.create_assessment_intake_link(:'acme', 'A-020') as intake_third \gset
select test.fails('a new intake link replaces the old one', format($$select public.assessment_intake_load(%L)$$, :'intake_second'));
select test.ok('a new intake link discards unsubmitted answers', public.get_assessment_intake(:'acme', 'A-020') ->> 'draftUpdatedAt' is null);
select public.assessment_intake_save(:'intake_third', '{"answers":{"RQ1":{"t":"Third draft"}}}');
select public.revoke_assessment_intake_link(:'acme', 'A-020');
select test.fails('a turned-off intake link stops working', format($$select public.assessment_intake_load(%L)$$, :'intake_third'));
select test.ok('turning off an intake link discards unsubmitted answers but keeps submitted ones', public.get_assessment_intake(:'acme', 'A-020') ->> 'draftUpdatedAt' is null and public.get_assessment_intake(:'acme', 'A-020') #>> '{response,answers,RQ1,t}' = 'An archive tool');
select public.create_assessment_intake_link(:'acme', 'A-020') as intake_live \gset
update public.assessments set data = data || '{"status":"Final"}' where display_id = 'A-020';
select test.fails('a final assessment refuses an intake link', format($$select public.assessment_intake_load(%L)$$, :'intake_live'));
select test.fails('a final assessment refuses intake answers', format($$select public.assessment_intake_save(%L, '{}')$$, :'intake_live'));
update public.assessments set data = data || '{"status":"Draft"}' where display_id = 'A-020';
reset role;
update public.assessment_intake_links set expires_at = now() - interval '1 minute' where org_id = :'acme';
select test.login(:carol, 'aal2', 'carol@acme.test');
set role authenticated;
select test.fails('an expired intake link stops working', format($$select public.assessment_intake_load(%L)$$, :'intake_live'));
select test.ok('an expired intake link shows as inactive', public.get_assessment_intake(:'acme', 'A-020') ->> 'expiresAt' is null);
delete from public.assessments where display_id = 'A-020';
reset role;
select test.ok('removing an assessment removes its intake link and answers', not exists (select 1 from public.assessment_intake_links) and not exists (select 1 from public.assessment_intake_responses));

-- ---- threat risk assessments ----
select test.login(:carol, 'aal2', 'carol@acme.test');
set role authenticated;
insert into public.threat_assessments (org_id, display_id, data) values (:'acme', 'T-001', '{"assetName":"Billing system"}');
select test.ok('analysts add threat assessments', test.count($$select 1 from public.threat_assessments$$) = 1);
select test.ok('threat assessment authorship stamped', (select created_by from public.threat_assessments where display_id = 'T-001') = :carol::uuid);
update public.threat_assessments set data = '{"assetName":"Billing system","status":"Completed"}' where display_id = 'T-001';
select test.fails('threat assessment id format enforced', format($$insert into public.threat_assessments (org_id, display_id, data) values (%L, 'A-001', '{}')$$, :'acme'));
select test.fails('threat assessment data must be an object', format($$insert into public.threat_assessments (org_id, display_id, data) values (%L, 'T-002', '[1]')$$, :'acme'));
reset role;

select test.login(:dave, 'aal2', 'dave@acme.test');
set role authenticated;
select test.ok('viewers cannot read threat assessments', test.count($$select 1 from public.threat_assessments$$) = 0);
select test.fails('viewers cannot add threat assessments', format($$insert into public.threat_assessments (org_id, display_id, data) values (%L, 'T-009', '{}')$$, :'acme'));
select test.ok('viewers cannot edit threat assessments', test.affected($$update public.threat_assessments set data = '{}'$$) = 0);
select test.ok('viewers cannot delete threat assessments', test.affected($$delete from public.threat_assessments$$) = 0);
reset role;

select test.login(:bob, 'aal2', 'bob@other.test');
set role authenticated;
select test.ok('tenant isolation: Bob sees no Acme threat assessments', test.count($$select 1 from public.threat_assessments$$) = 0);
select test.fails('Bob cannot add a threat assessment to Acme', format($$insert into public.threat_assessments (org_id, display_id, data) values (%L, 'T-010', '{}')$$, :'acme'));
reset role;

-- A viewer sees only the assessments naming them, matched on the admin-controlled directory.
select test.login(:carol, 'aal2', 'carol@acme.test');
set role authenticated;
insert into public.threat_assessments (org_id, display_id, data) values
  (:'acme', 'T-002', '{"assetName":"Risk owner","riskOwner":"Dave Lee"}'),
  (:'acme', 'T-003', '{"assetName":"Asset owner","assetOwner":" dave lee "}'),
  (:'acme', 'T-004', '{"assetName":"Someone else","riskOwner":"Fay Ross","assetOwner":"Fay Ross"}');
reset role;

select test.login(:dave, 'aal2', 'dave@acme.test');
set role authenticated;
select test.ok('a profile name alone does not match a viewer to an assessment', test.count($$select 1 from public.threat_assessments$$) = 0);
reset role;

select test.login(:alice, 'aal2', 'alice@acme.test');
set role authenticated;
select public.save_person(:'acme', '{"email": "dave@acme.test", "first_name": "Dave", "last_name": "Lee"}');
reset role;

select test.login(:dave, 'aal2', 'dave@acme.test');
set role authenticated;
select test.ok('viewers read assessments naming them as asset or risk owner',
  (select array_agg(display_id order by display_id) from public.threat_assessments) = array['T-002', 'T-003']);
select test.ok('viewers cannot edit their own threat assessment', test.affected($$update public.threat_assessments set data = '{}' where display_id = 'T-002'$$) = 0);
select test.ok('viewers cannot delete their own threat assessment', test.affected($$delete from public.threat_assessments where display_id = 'T-002'$$) = 0);
select test.fails('viewers cannot add a threat assessment naming themselves', format($$insert into public.threat_assessments (org_id, display_id, data) values (%L, 'T-011', '{"riskOwner":"Dave Lee"}')$$, :'acme'));
select public.save_profile(:'acme', :dave, 'Fay', 'Ross', 'Senior Auditor', '', 'Internal Audit');
select test.ok('renaming your profile does not reveal someone else''s assessment', not exists (select 1 from public.threat_assessments where display_id = 'T-004'));
select public.save_profile(:'acme', :dave, 'Dave', 'Lee', 'Senior Auditor', '', 'Internal Audit');
reset role;

select test.login(:dave, 'aal1', 'dave@acme.test');
set role authenticated;
select test.ok('a viewer without multi-factor sign-in sees no threat assessments', test.count($$select 1 from public.threat_assessments$$) = 0);
reset role;

select test.login(:bob, 'aal2', 'bob@other.test');
set role authenticated;
select test.ok('another workspace''s member cannot read an assessment by name', test.count($$select 1 from public.threat_assessments$$) = 0);
reset role;

select test.login(:carol, 'aal2', 'carol@acme.test');
set role authenticated;
select test.ok('analysts read every threat assessment', test.count($$select 1 from public.threat_assessments$$) = 4);
reset role;

-- Links for someone without an account.
select test.login(:carol, 'aal2', 'carol@acme.test');
set role authenticated;
insert into public.threat_assessments (org_id, display_id, data) values (:'acme', 'T-005',
  '{"assetName":"Linked asset","description":"Public text","status":"In progress","riskOwner":"secret-owner","summaryNotes":"secret-notes","impact":{"B1":{"c":"secret-impact"}},"gapDetails":{"AC-01":{"comment":"secret-gap"}},"profile":{"assetTypes":["app"],"auth":{"otp":true},"cloud":"Yes","ai":"No","vendor":"Hosting Co","notes":"Internal detail","deployment":"Public"},"answers":{"AC-01":{"status":"No"}}}');
select public.create_tra_link(:'acme', 'T-005') as link_token \gset
select test.ok('tokens are long and random', length(:'link_token') = 64);
reset role;
select test.ok('only a hash of the token is stored', not exists (select 1 from public.threat_assessment_links where token_hash = :'link_token'));

select test.login(:dave, 'aal2', 'dave@acme.test');
set role authenticated;
select test.fails('viewers cannot create links', format($$select public.create_tra_link(%L, 'T-002')$$, :'acme'));
select test.fails('viewers cannot read outside answers', format($$select public.get_tra_outside(%L, 'T-002')$$, :'acme'));
reset role;

select test.login(:bob, 'aal2', 'bob@other.test');
set role authenticated;
select test.fails('another workspace cannot create links', format($$select public.create_tra_link(%L, 'T-005')$$, :'acme'));
select test.fails('another workspace cannot read outside answers', format($$select public.get_tra_outside(%L, 'T-005')$$, :'acme'));
reset role;

select set_config('request.jwt.claims', '{}', false);
set role anon;
select test.ok('a link shows the asset to someone without an account', public.tra_outside_load(:'link_token') ->> 'assetName' = 'Linked asset');
select test.ok('a link returns the workspace''s framework', public.tra_outside_load(:'link_token') ->> 'framework' = 'csf2');
select test.ok('a link starts from the assessment''s step 1 choices, so it lists the same controls',
  public.tra_outside_load(:'link_token') -> 'scope' = '{"assetTypes":["app"],"auth":{"otp":true},"cloud":"Yes","ai":"No"}'::jsonb);
select test.ok('a link leaves out free-text details unless they''re shared', public.tra_outside_load(:'link_token')::text not like '%Hosting Co%'
  and public.tra_outside_load(:'link_token')::text not like '%Internal detail%' and public.tra_outside_load(:'link_token')::text not like '%Public text%');
select test.ok('a link shares no answers or free text by default', public.tra_outside_load(:'link_token') -> 'seed' = 'null'::jsonb);
select test.ok('a link never returns owners, the analyst''s impact, gaps or notes', public.tra_outside_load(:'link_token')::text not like '%secret-%');
select test.fails('a wrong token is refused', $$select public.tra_outside_load(repeat('a', 64))$$);
select test.fails('a malformed token is refused', $$select public.tra_outside_load('x')$$);
select test.fails('no token is refused', $$select public.tra_outside_save(null, '{}')$$);
select test.fails('no outside access to the links table', $$select 1 from public.threat_assessment_links$$);
select test.fails('no outside access to the responses table', $$select 1 from public.threat_assessment_responses$$);
select test.fails('no outside access to assessments', $$select 1 from public.threat_assessments$$);
select test.fails('no outside link creation', format($$select public.create_tra_link(%L, 'T-005')$$, :'acme'));
select test.fails('no outside reading of answers', format($$select public.get_tra_outside(%L, 'T-005')$$, :'acme'));
select public.tra_outside_save(:'link_token', '{"contributor":{"name":"Pat Doe","email":"pat@example.test","extra":"x"},"description":"From Pat","answers":{"AC-01":{"status":"Yes"}},"gapDetails":{"x":"injected"},"riskOwner":"injected","impact":{"B1":{"c":"A"}}}');
select test.fails('a threat posture link refuses answers to unknown controls', format($$select public.tra_outside_save(%L, '{"answers":{"not a control":{"status":"Yes"}}}')$$, :'link_token'));
select test.fails('a threat posture link refuses an impact rating outside the scale', format($$select public.tra_outside_save(%L, '{"impact":{"B1":{"c":"Z"}}}')$$, :'link_token'));
select test.fails('a threat posture link refuses a status outside the list', format($$select public.tra_outside_save(%L, '{"answers":{"AC-01":{"status":"Maybe"}}}')$$, :'link_token'));
select test.fails('submitting needs a name', format($$select public.tra_outside_save(%L, '{"description":"x"}', true)$$, :'link_token'));
select test.fails('a response must be an object', format($$select public.tra_outside_save(%L, '[1]')$$, :'link_token'));
select test.fails('oversized responses are refused', format($$select public.tra_outside_save(%L, jsonb_build_object('description', (select string_agg(md5(i::text), '') from generate_series(1, 40000) i)))$$, :'link_token'));
select test.ok('a saved draft comes back with the link', public.tra_outside_load(:'link_token') #>> '{response,description}' = 'From Pat');
select test.ok('contact details never go back to the form', public.tra_outside_load(:'link_token')::text not like '%pat@example%' and public.tra_outside_load(:'link_token')::text not like '%Pat Doe%');
reset role;

select test.login(:carol, 'aal2', 'carol@acme.test');
set role authenticated;
select test.ok('analysts see a draft in progress', public.get_tra_outside(:'acme', 'T-005') ->> 'draftBy' = 'Pat Doe' and public.get_tra_outside(:'acme', 'T-005') ->> 'submittedAt' is null);
reset role;

select set_config('request.jwt.claims', '{}', false);
set role anon;
select test.ok('submitting works without an account', public.tra_outside_save(:'link_token', '{"contributor":{"name":"=Pat Doe","email":"alice@acme.test"},"description":"From Pat","answers":{"AC-01":{"status":"Yes"}},"riskOwner":"injected"}', true) ->> 'status' = 'submitted');
select test.fails('submitting ends the link', format($$select public.tra_outside_load(%L)$$, :'link_token'));
select test.fails('a link allows only one submission', format($$select public.tra_outside_save(%L, '{"contributor":{"name":"Again"}}', true)$$, :'link_token'));
reset role;

select test.ok('unexpected response parts are dropped', not exists (select 1 from public.threat_assessment_responses where response ?| array['gapDetails', 'riskOwner', 'impact'] or response -> 'contributor' ? 'extra'));
select test.ok('outside answers do not change the assessment', (select data #>> '{answers,AC-01,status}' from public.threat_assessments where display_id = 'T-005' and org_id = :'acme') = 'No'
  and (select data ->> 'description' from public.threat_assessments where display_id = 'T-005' and org_id = :'acme') = 'Public text');
select test.ok('a typed email cannot pass as a member in the audit log', exists (select 1 from public.audit_log where entity = 'threat_assessment_responses' and action = 'submit' and entity_id = 'T-005' and actor is null and actor_email = 'outside link' and details ->> 'entered_email' = 'alice@acme.test')
  and not exists (select 1 from public.audit_log where entity = 'threat_assessment_responses' and actor_email = 'alice@acme.test'));

select test.login(:carol, 'aal2', 'carol@acme.test');
set role authenticated;
select test.ok('analysts read submitted answers', public.get_tra_outside(:'acme', 'T-005') #>> '{response,description}' = 'From Pat' and public.get_tra_outside(:'acme', 'T-005') ->> 'submittedAt' is not null);
select test.ok('a submitted link shows as inactive', public.get_tra_outside(:'acme', 'T-005') ->> 'expiresAt' is null);
select test.fails('analysts cannot read the links table', $$select 1 from public.threat_assessment_links$$);
select public.create_tra_link(:'acme', 'T-005', true) as shared_token \gset
select test.ok('a link can share existing answers when chosen', public.tra_outside_load(:'shared_token') #>> '{seed,description}' = 'Public text' and public.get_tra_outside(:'acme', 'T-005') -> 'shareExisting' = 'true'::jsonb);
select test.ok('shared answers still leave out owners, impact, gaps and notes', public.tra_outside_load(:'shared_token')::text not like '%secret-%');
select test.ok('a new link cannot see earlier submitted answers', public.tra_outside_load(:'shared_token') -> 'response' = 'null'::jsonb);
select public.tra_outside_save(:'shared_token', '{"description":"Second draft"}');
select test.ok('a new draft does not replace submitted answers', public.get_tra_outside(:'acme', 'T-005') #>> '{response,description}' = 'From Pat');
select public.create_tra_link(:'acme', 'T-005') as new_token \gset
select test.fails('a new link replaces the old one', format($$select public.tra_outside_load(%L)$$, :'shared_token'));
select test.ok('a new link discards unsubmitted answers', public.get_tra_outside(:'acme', 'T-005') ->> 'draftUpdatedAt' is null and public.tra_outside_load(:'new_token') -> 'response' = 'null'::jsonb);
select public.tra_outside_save(:'new_token', '{"description":"Third draft"}');
select public.revoke_tra_link(:'acme', 'T-005');
select test.fails('a turned-off link stops working', format($$select public.tra_outside_load(%L)$$, :'new_token'));
select test.ok('turning off a link discards unsubmitted answers but keeps submitted ones', public.get_tra_outside(:'acme', 'T-005') ->> 'draftUpdatedAt' is null and public.get_tra_outside(:'acme', 'T-005') #>> '{response,description}' = 'From Pat');
select public.create_tra_link(:'acme', 'T-005') as live_token \gset
update public.threat_assessments set data = data || '{"status":"Completed"}' where display_id = 'T-005';
select test.fails('a completed assessment refuses a link', format($$select public.tra_outside_load(%L)$$, :'live_token'));
select test.fails('a completed assessment refuses answers', format($$select public.tra_outside_save(%L, '{}')$$, :'live_token'));
update public.threat_assessments set data = data || '{"status":"In progress"}' where display_id = 'T-005';
reset role;
select test.ok('new links last 14 days', (select expires_at from public.threat_assessment_links where org_id = :'acme') between now() + interval '13 days' and now() + interval '14 days 1 minute');
update public.threat_assessment_links set expires_at = now() - interval '1 minute' where org_id = :'acme';
select test.login(:carol, 'aal2', 'carol@acme.test');
set role authenticated;
select test.fails('an expired link stops working', format($$select public.tra_outside_load(%L)$$, :'live_token'));
select test.ok('an expired link shows as inactive', public.get_tra_outside(:'acme', 'T-005') ->> 'expiresAt' is null);
select public.create_tra_link(:'acme', 'T-005') as last_token \gset
delete from public.threat_assessments where display_id = 'T-005';
insert into public.threat_assessments (org_id, display_id, data) values (:'acme', 'T-005', '{"assetName":"Reused ID"}');
select test.fails('deleting an assessment ends its link, even if the ID is reused', format($$select public.tra_outside_load(%L)$$, :'last_token'));
select test.ok('deleting an assessment removes its outside answers', public.get_tra_outside(:'acme', 'T-005') ->> 'response' is null);
delete from public.threat_assessments where display_id = 'T-005';
reset role;

select test.login(:alice, 'aal2', 'alice@acme.test');
set role authenticated;
select public.delete_person(:'acme', 'dave@acme.test');
reset role;

-- ---- saved briefings ----
select test.login(:carol, 'aal2', 'carol@acme.test');
set role authenticated;
select public.save_briefing(:'acme', '{"generatedAt":"2026-10-01T00:00:00Z"}');
select public.save_briefing(:'acme', '{"generatedAt":"2026-10-27T00:00:00Z"}');
select test.ok('analyst can save briefing; new one replaces the old',
  (select array_agg(report ->> 'generatedAt') from public.briefings) = array['2026-10-27T00:00:00Z']);
select test.ok('briefing authorship stamped by the server', (select updated_by from public.briefings) = :carol::uuid);
select test.fails('briefing must be an object', format($$select public.save_briefing(%L, '[1]')$$, :'acme'));
select test.fails('no direct briefing writes', format($$insert into public.briefings (org_id, report) values (%L, '{}')$$, :'acme'));
reset role;

select test.login(:carol, 'aal2', 'carol@acme.test');
set role authenticated;
select test.ok('analysts read vendors', test.count($$select 1 from public.vendors$$) > 0);
select test.ok('analysts read vendor responses', test.count($$select 1 from public.intake_responses$$) = 1);
select test.ok('analysts read vendor documents', test.count($$select 1 from public.intake_documents$$) = 1);
reset role;

select test.login(:dave, 'aal2', 'dave@acme.test');
set role authenticated;
select test.ok('viewers cannot read the briefing', test.count($$select 1 from public.briefings$$) = 0);
select test.fails('viewer cannot save briefing', format($$select public.save_briefing(%L, '{}')$$, :'acme'));
select test.fails('viewer cannot delete briefing', $$delete from public.briefings$$);
reset role;

select test.login(:bob, 'aal2', 'bob@other.test');
set role authenticated;
select test.ok('tenant isolation: Bob sees no Acme briefing', test.count($$select 1 from public.briefings$$) = 0);
select test.fails('tenant isolation: Bob cannot save Acme briefing', format($$select public.save_briefing(%L, '{}')$$, :'acme'));
reset role;

select test.login(:erin, 'aal2', 'erin@acme.test');
set role authenticated;
select test.ok('unverified email cannot accept invitation', public.accept_invitations() = 0);
reset role;

-- ---- admin rules ----
select test.login(:alice, 'aal2', 'alice@acme.test');
set role authenticated;
select public.set_member_role(:'acme', :carol, 'admin');
reset role;
select test.login(:carol, 'aal2', 'carol@acme.test');
set role authenticated;
select test.ok('admin can read audit log', test.count($$select 1 from public.audit_log$$) > 0);
select test.ok('admin can see invitations', test.count($$select 1 from public.invitations$$) > 0);
select public.invite_member(:'acme', 'frank@acme.test', 'analyst');
select test.fails('admin cannot invite admins', format($$select public.invite_member(%L, 'g@acme.test', 'admin')$$, :'acme'));
select test.fails('admin cannot demote owner', format($$select public.set_member_role(%L, %L, 'viewer')$$, :'acme', :alice));
select test.fails('admin cannot remove owner', format($$select public.remove_member(%L, %L)$$, :'acme', :alice));
select test.fails('admin cannot promote to owner', format($$select public.set_member_role(%L, %L, 'owner')$$, :'acme', :dave));
select public.set_member_role(:'acme', :dave, 'analyst');
select test.ok('admin can promote viewer to analyst', (select role from public.memberships where user_id = :dave::uuid) = 'analyst');
select public.set_org_logo(:'acme', 'data:image/png;base64,iVBORw0KGgo=');
select test.ok('admin can set the logo', (select logo from public.organizations where id = :'acme') = 'data:image/png;base64,iVBORw0KGgo=');
select test.fails('logo must be an image data URL', format($$select public.set_org_logo(%L, 'javascript:alert(1)')$$, :'acme'));
select test.fails('logo cannot be an HTML data URL', format($$select public.set_org_logo(%L, 'data:text/html;base64,PHA+')$$, :'acme'));
select public.set_org_tra_framework(:'acme', 'sp80053');
select test.ok('admin can change the framework', (select tra_framework from public.organizations where id = :'acme') = 'sp80053');
select test.fails('framework must be a known one', format($$select public.set_org_tra_framework(%L, 'iso27001')$$, :'acme'));
select public.set_org_vendor_questionnaire(:'acme', '{"hidden":["GOV2"]}'::jsonb);
select test.ok('admin can change the vendor questionnaire', (select vendor_questionnaire -> 'hidden' ->> 0 from public.organizations where id = :'acme') = 'GOV2');
select test.fails('vendor questionnaire must be an object', format($$select public.set_org_vendor_questionnaire(%L, '[1]'::jsonb)$$, :'acme'));
select public.set_org_risk_sections(:'acme', '[{"id":"gov1","name":"Governance"}]'::jsonb);
select test.ok('admin can set the risk register sections', (select risk_sections -> 0 ->> 'name' from public.organizations where id = :'acme') = 'Governance');
select test.fails('risk sections need an id and a name', format($$select public.set_org_risk_sections(%L, '[{"id":"x"}]'::jsonb)$$, :'acme'));
select public.set_org_risk_sections(:'acme', '[{"id":"gov1","name":"Governance","fields":[{"id":"own1","label":"Owner approved","type":"yesno"}]}]'::jsonb);
select test.ok('admin can add fields to a risk register section', (select risk_sections -> 0 -> 'fields' ->> 0 from public.organizations where id = :'acme') like '%Owner approved%');
select test.fails('risk fields need a known type', format($$select public.set_org_risk_sections(%L, '[{"id":"gov1","name":"Governance","fields":[{"id":"own1","label":"x","type":"script"}]}]'::jsonb)$$, :'acme'));
select test.fails('risk fields must be a list in a section', format($$select public.set_org_risk_sections(%L, '[{"id":"gov1","name":"Governance","fields":{}}]'::jsonb)$$, :'acme'));
select test.fails('risk sections must be a list', format($$select public.set_org_risk_sections(%L, '{}'::jsonb)$$, :'acme'));
select public.set_org_internal_standards(:'acme', '["ISO 27001","NIST CSF 2.0"]'::jsonb);
select test.ok('admin can set the internal standards', (select internal_standards ->> 1 from public.organizations where id = :'acme') = 'NIST CSF 2.0');
select test.fails('internal standards must be a list', format($$select public.set_org_internal_standards(%L, '{}'::jsonb)$$, :'acme'));
select test.fails('internal standards must be names', format($$select public.set_org_internal_standards(%L, '[1]'::jsonb)$$, :'acme'));
select public.set_org_risk_appetite(:'acme', '{"default":"Medium","categories":{"Data Breach":"Low"}}'::jsonb);
select test.ok('admin can set the risk appetite', (select risk_appetite ->> 'default' from public.organizations where id = :'acme') = 'Medium'
  and (select risk_appetite -> 'categories' ->> 'Data Breach' from public.organizations where id = :'acme') = 'Low');
select test.fails('risk appetite needs a default level', format($$select public.set_org_risk_appetite(%L, '{"categories":{"Data Breach":"Low"}}'::jsonb)$$, :'acme'));
select test.fails('risk appetite default must be a known level', format($$select public.set_org_risk_appetite(%L, '{"default":"Severe"}'::jsonb)$$, :'acme'));
select test.fails('risk appetite must be an object', format($$select public.set_org_risk_appetite(%L, '["Medium"]'::jsonb)$$, :'acme'));
select test.fails('risk appetite category limits must be levels', format($$select public.set_org_risk_appetite(%L, '{"default":"Medium","categories":{"Data Breach":"Severe"}}'::jsonb)$$, :'acme'));
select test.fails('risk appetite category limits must be an object', format($$select public.set_org_risk_appetite(%L, '{"default":"Medium","categories":["Low"]}'::jsonb)$$, :'acme'));
select test.ok('a failed risk appetite change keeps the last one', (select risk_appetite ->> 'default' from public.organizations where id = :'acme') = 'Medium');
select public.set_org_risk_appetite(:'acme', 'null'::jsonb);
select test.ok('admin can clear the risk appetite', (select risk_appetite from public.organizations where id = :'acme') is null);
select public.set_org_vendor_sections(:'acme', '[{"id":"sec1","name":"Security review","fields":[{"id":"fld1","label":"Last pen test","type":"date"}]}]'::jsonb);
select test.ok('admin can add vendor sections and fields', (select vendor_sections -> 0 -> 'fields' ->> 0 from public.organizations where id = :'acme') like '%Last pen test%');
select test.fails('vendor fields need a known type', format($$select public.set_org_vendor_sections(%L, '[{"id":"sec1","name":"Security review","fields":[{"id":"fld1","label":"x","type":"script"}]}]'::jsonb)$$, :'acme'));
select test.ok('members read the logo', test.count($$select 1 from public.organizations where logo is not null$$) = 1);
select test.fails('audit log is append-only (update)', $$update public.audit_log set action = 'x'$$);
select test.fails('audit log is append-only (delete)', $$delete from public.audit_log$$);
reset role;

-- ---- organisation logo ----
select test.login(:dave, 'aal2', 'dave@acme.test');
set role authenticated;
select test.fails('analysts cannot clear the briefing', format($$select public.clear_briefing(%L)$$, :'acme'));
select test.fails('analysts cannot change the framework', format($$select public.set_org_tra_framework(%L, 'csf2')$$, :'acme'));
select test.fails('analysts cannot change the risk register sections', format($$select public.set_org_risk_sections(%L, '[]'::jsonb)$$, :'acme'));
select test.fails('analysts cannot change the vendor sections', format($$select public.set_org_vendor_sections(%L, '[]'::jsonb)$$, :'acme'));
select test.fails('analysts cannot set the logo', format($$select public.set_org_logo(%L, 'data:image/png;base64,iVBORw0KGgo=')$$, :'acme'));
select test.fails('analysts cannot change the vendor questionnaire', format($$select public.set_org_vendor_questionnaire(%L, '{}'::jsonb)$$, :'acme'));
reset role;
select test.login(:bob, 'aal2', 'bob@other.test');
set role authenticated;
select test.fails('tenant isolation: Bob cannot change Acme''s framework', format($$select public.set_org_tra_framework(%L, 'csf2')$$, :'acme'));
select test.fails('tenant isolation: Bob cannot change Acme''s risk register sections', format($$select public.set_org_risk_sections(%L, '[]'::jsonb)$$, :'acme'));
select test.fails('tenant isolation: Bob cannot set Acme''s logo', format($$select public.set_org_logo(%L, 'data:image/png;base64,iVBORw0KGgo=')$$, :'acme'));
select test.fails('tenant isolation: Bob cannot change Acme''s vendor questionnaire', format($$select public.set_org_vendor_questionnaire(%L, '{}'::jsonb)$$, :'acme'));
select test.fails('tenant isolation: Bob cannot read Acme''s risk history', format($$select * from public.risk_history(%L, 'R-002')$$, :'acme'));
reset role;

-- ---- owner rules ----
select test.login(:alice, 'aal2', 'alice@acme.test');
set role authenticated;
select test.fails('last owner cannot step down', format($$select public.set_member_role(%L, %L, 'admin')$$, :'acme', :alice));
select test.fails('last owner cannot leave', format($$select public.remove_member(%L, %L)$$, :'acme', :alice));
update public.organizations set name = 'Acme Corp' where id = :'acme';
select test.ok('owner can rename organisation', (select name from public.organizations where id = :'acme') = 'Acme Corp');
select public.remove_member(:'acme', :dave);
select test.ok('owner can remove member', test.count($$select 1 from public.memberships where user_id = '00000000-0000-0000-0000-00000000000d'$$) = 0);
reset role;

-- ---- audit trail contents (checked as superuser) ----
select test.ok('audit records the old and new value of a key field', exists (select 1 from public.audit_log where entity = 'risks' and entity_id = 'R-002' and action = 'update'
  and details -> 'changes' -> 'title' = '{"from": "Phishing", "to": "Phishing v2"}'::jsonb and details -> 'changes' -> 'owner' = '{"from": "", "to": "CFO"}'::jsonb));
select test.ok('the list of changed fields is still recorded', exists (select 1 from public.audit_log where entity = 'risks' and entity_id = 'R-002' and action = 'update' and details -> 'changed' ?& array['title', 'owner']));
select test.ok('audit records risk insert', exists (select 1 from public.audit_log where entity = 'risks' and action = 'insert' and entity_id = 'R-001'));
select test.ok('audit records changed fields', exists (select 1 from public.audit_log where entity = 'risks' and action = 'update' and details -> 'changed' ? 'owner'));
select test.ok('audit records actor email', exists (select 1 from public.audit_log where actor_email = 'carol@acme.test'));
select test.ok('audit records role change', exists (select 1 from public.audit_log where entity = 'memberships' and action = 'update'));
select test.ok('audit records briefing replacement', exists (select 1 from public.audit_log where entity = 'briefings' and action = 'update'));
select test.ok('audit records profile changes', exists (select 1 from public.audit_log where entity = 'profiles' and entity_id = 'dave@acme.test'));
select test.ok('audit records directory imports', exists (select 1 from public.audit_log where entity = 'people' and action = 'import'));
select test.ok('audit records assessment changes', exists (select 1 from public.audit_log where entity = 'assessments' and action = 'update' and entity_id = 'A-001'));
select test.ok('audit records threat assessment changes', exists (select 1 from public.audit_log where entity = 'threat_assessments' and action = 'update' and entity_id = 'T-001'));
select test.ok('audit records framework changes', exists (select 1 from public.audit_log where entity = 'organizations' and details -> 'changed' ? 'tra_framework'));
select test.ok('audit records vendor questionnaire changes', exists (select 1 from public.audit_log where entity = 'organizations' and details -> 'changed' ? 'vendor_questionnaire'));
select test.ok('audit records logo changes', exists (select 1 from public.audit_log where entity = 'organizations' and details -> 'changed' ? 'logo'));
select test.ok('audit records member removal', exists (select 1 from public.audit_log where entity = 'memberships' and action = 'delete'));
select test.fails('audit log append-only even for the database owner', $$delete from public.audit_log$$);

-- ---- Risk history ----
select test.login(:alice, 'aal2', 'alice@acme.test');
set role authenticated;
insert into public.risks (org_id, display_id, data) values (:'acme', 'R-050', '{"title":"First","status":"Identified"}');
update public.risks set data = '{"title":"First","status":"Treating","memo":"not a key field","comments":[{"text":"private words"}]}' where display_id = 'R-050';
select test.ok('history lists the insert and the update, newest first',
  (select string_agg(action, ',' order by ord) from (select action, row_number() over () as ord from public.risk_history(:'acme', 'R-050')) h) = 'update,insert');
select test.ok('history records a key field''s old and new value',
  (select changes -> 'status' from public.risk_history(:'acme', 'R-050') where action = 'update') = '{"from": "Identified", "to": "Treating"}'::jsonb);
select test.ok('fields that are not key fields are not recorded with values',
  (select not (changes ? 'memo') and not (changes ? 'comments') from public.risk_history(:'acme', 'R-050') where action = 'update'));
update public.risks set data = jsonb_set(data, '{title}', to_jsonb(repeat('x', 500))) where display_id = 'R-050';
select test.ok('a long value is cut to 200 characters',
  (select max(length(changes -> 'title' ->> 'to')) from public.risk_history(:'acme', 'R-050') where changes ? 'title') = 200);
delete from public.risks where display_id = 'R-050';
insert into public.risks (org_id, display_id, data) values (:'acme', 'R-050', '{"title":"Reused number"}');
select test.ok('a deleted risk''s history does not carry over to a new risk with the same number',
  (select count(*) from public.risk_history(:'acme', 'R-050')) = 1);
select test.ok('history of a risk that does not exist is empty', (select count(*) from public.risk_history(:'acme', 'R-404')) = 0);
reset role;
select test.login(:bob, 'aal2', 'bob@other.test');
set role authenticated;
select test.ok('a risk number in another workspace shows nothing of Acme''s', (select count(*) from public.risk_history((select org_id from public.my_organizations() limit 1), 'R-050')) = 0);
reset role;
select test.login(:alice, 'aal1', 'alice@acme.test');
set role authenticated;
select test.fails('history needs an MFA session', format($$select * from public.risk_history(%L, 'R-002')$$, :'acme'));
reset role;
select test.ok('the history function is not open to anonymous callers', not has_function_privilege('anon', 'public.risk_history(uuid, text)', 'execute'));

-- ---- Evidence files on a risk ----
-- Alice (owner) adds files to a new risk. The contents are tiny but start the way each type does: %PDF-1.4, the PNG
-- signature, a JPEG start and the text "hello".
select test.login(:alice, 'aal2', 'alice@acme.test');
set role authenticated;
insert into public.risks (org_id, display_id, data) values (:'acme', 'R-051', '{"title":"Needs proof"}');
insert into public.risk_evidence (org_id, risk_ref, name, media_type, size, data) values (:'acme', 'R-051', 'policy.pdf', 'application/pdf', 99999, 'JVBERi0xLjQK');
select test.ok('an analyst or above can add a PDF', test.count($$select 1 from public.risk_evidence where name = 'policy.pdf'$$) = 1);
select test.ok('the size is worked out from the file, not taken from the client', (select size from public.risk_evidence where name = 'policy.pdf') = 9);
select test.ok('who added a file is stamped by the server', (select created_by from public.risk_evidence where name = 'policy.pdf') = :alice::uuid);
insert into public.risk_evidence (org_id, risk_ref, name, media_type, size, data) values
  (:'acme', 'R-051', 'shot.png', 'image/png', 1, 'iVBORw0KGgoAAAANSUhEUg=='),
  (:'acme', 'R-051', 'photo.jpg', 'image/jpeg', 1, '/9j/4AAQSkZJRg=='),
  (:'acme', 'R-051', 'notes.txt', 'text/plain', 1, 'aGVsbG8=');
select test.ok('PNG, JPEG and text files can be added too', test.count($$select 1 from public.risk_evidence$$) = 4);
select test.fails('a web page cannot be stored as an image', format($$insert into public.risk_evidence (org_id, risk_ref, name, media_type, size, data) values (%L, 'R-051', 'x.png', 'image/png', 1, 'PGh0bWw+')$$, :'acme'));
select test.fails('a web page cannot be stored as a PDF', format($$insert into public.risk_evidence (org_id, risk_ref, name, media_type, size, data) values (%L, 'R-051', 'x.pdf', 'application/pdf', 1, 'PGh0bWw+')$$, :'acme'));
select test.fails('a binary file cannot be stored as text', format($$insert into public.risk_evidence (org_id, risk_ref, name, media_type, size, data) values (%L, 'R-051', 'x.txt', 'text/plain', 1, 'AGhp')$$, :'acme'));
select test.fails('data that is not base64 is refused', format($$insert into public.risk_evidence (org_id, risk_ref, name, media_type, size, data) values (%L, 'R-051', 'x.txt', 'text/plain', 1, 'not base64!!')$$, :'acme'));
select test.fails('empty data is refused', format($$insert into public.risk_evidence (org_id, risk_ref, name, media_type, size, data) values (%L, 'R-051', 'x.txt', 'text/plain', 1, '')$$, :'acme'));
select test.fails('SVG is refused', format($$insert into public.risk_evidence (org_id, risk_ref, name, media_type, size, data) values (%L, 'R-051', 'x.svg', 'image/svg+xml', 1, 'aGVsbG8=')$$, :'acme'));
select test.fails('HTML is refused', format($$insert into public.risk_evidence (org_id, risk_ref, name, media_type, size, data) values (%L, 'R-051', 'x.html', 'text/html', 1, 'aGVsbG8=')$$, :'acme'));
select test.fails('a file name is unique within its risk', format($$insert into public.risk_evidence (org_id, risk_ref, name, media_type, size, data) values (%L, 'R-051', 'policy.pdf', 'application/pdf', 1, 'JVBERi0xLjQK')$$, :'acme'));
select test.fails('evidence needs an existing risk', format($$insert into public.risk_evidence (org_id, risk_ref, name, media_type, size, data) values (%L, 'R-999', 'x.txt', 'text/plain', 1, 'aGVsbG8=')$$, :'acme'));
select test.fails('who added a file cannot be set by the client', format($$insert into public.risk_evidence (org_id, risk_ref, name, media_type, size, data, created_by) values (%L, 'R-051', 'y.txt', 'text/plain', 1, 'aGVsbG8=', %L)$$, :'acme', :bob));
select test.fails('a file cannot be changed once added', $$update public.risk_evidence set name = 'renamed.pdf'$$);
select test.fails('a file cannot be larger than 5 MB', format($$insert into public.risk_evidence (org_id, risk_ref, name, media_type, size, data) values (%L, 'R-051', 'big.txt', 'text/plain', 1, repeat('QUJD', 1900000))$$, :'acme'));
insert into public.risk_evidence (org_id, risk_ref, name, media_type, size, data)
  select :'acme', 'R-051', 'more-' || n || '.txt', 'text/plain', 1, 'aGVsbG8=' from generate_series(1, 6) n;
select test.ok('a risk can have 10 files', test.count($$select 1 from public.risk_evidence$$) = 10);
select test.fails('an 11th file is refused', format($$insert into public.risk_evidence (org_id, risk_ref, name, media_type, size, data) values (%L, 'R-051', 'eleventh.txt', 'text/plain', 1, 'aGVsbG8=')$$, :'acme'));
reset role;
select test.ok('adding a file is audited, without its contents', exists (select 1 from public.audit_log where entity = 'risk_evidence' and entity_id = 'R-051' and action = 'insert'
  and details ->> 'name' = 'policy.pdf' and (details ->> 'size')::int = 9 and not (details ? 'data')));

-- A viewer can read and download, but not add or remove.
insert into public.memberships (org_id, user_id, role, email) values (:'acme', :dave, 'viewer', 'dave@acme.test');
select test.login(:dave, 'aal2', 'dave@acme.test');
set role authenticated;
select test.ok('a viewer can read a risk''s evidence', test.count($$select 1 from public.risk_evidence where risk_ref = 'R-051'$$) = 10);
-- (on R-001, which has no files, so only the viewer's role stops it)
select test.fails('a viewer cannot add evidence', format($$insert into public.risk_evidence (org_id, risk_ref, name, media_type, size, data) values (%L, 'R-001', 'v.txt', 'text/plain', 1, 'aGVsbG8=')$$, :'acme'));
select test.ok('a viewer cannot remove evidence', test.affected($$delete from public.risk_evidence$$) = 0);
reset role;

-- Another workspace, and a session without MFA, see nothing and can add nothing.
select test.login(:bob, 'aal2', 'bob@other.test');
set role authenticated;
select test.ok('tenant isolation: Bob cannot read Acme''s evidence', test.count($$select 1 from public.risk_evidence$$) = 0);
select test.fails('tenant isolation: Bob cannot add evidence to Acme', format($$insert into public.risk_evidence (org_id, risk_ref, name, media_type, size, data) values (%L, 'R-051', 'b.txt', 'text/plain', 1, 'aGVsbG8=')$$, :'acme'));
select test.ok('tenant isolation: Bob cannot remove Acme''s evidence', test.affected($$delete from public.risk_evidence$$) = 0);
reset role;
select test.login(:alice, 'aal1', 'alice@acme.test');
set role authenticated;
select test.ok('a session without MFA cannot read evidence', test.count($$select 1 from public.risk_evidence$$) = 0);
select test.fails('a session without MFA cannot add evidence', format($$insert into public.risk_evidence (org_id, risk_ref, name, media_type, size, data) values (%L, 'R-051', 'm.txt', 'text/plain', 1, 'aGVsbG8=')$$, :'acme'));
reset role;
select test.ok('anonymous callers have no access to evidence', not has_table_privilege('anon', 'public.risk_evidence', 'select') and not has_table_privilege('anon', 'public.risk_evidence', 'insert'));

-- An analyst can remove a file; deleting the risk removes the rest, so a new risk with the same number starts empty.
select test.login(:carol, 'aal2', 'carol@acme.test');
set role authenticated;
select test.ok('an analyst can remove a file', test.affected($$delete from public.risk_evidence where name = 'notes.txt'$$) = 1);
reset role;
select test.ok('removing a file is audited', exists (select 1 from public.audit_log where entity = 'risk_evidence' and entity_id = 'R-051' and action = 'delete' and details ->> 'name' = 'notes.txt'));
select test.login(:alice, 'aal2', 'alice@acme.test');
set role authenticated;
delete from public.risks where display_id = 'R-051';
insert into public.risks (org_id, display_id, data) values (:'acme', 'R-051', '{"title":"New risk, same number"}');
select test.ok('deleting a risk removes its evidence', test.count($$select 1 from public.risk_evidence where risk_ref = 'R-051'$$) = 0);
reset role;

-- ---- Exception approvals and the approver role ----
-- Roles rank viewer < analyst < approver < admin < owner. Carol is an analyst, Dave a viewer, Alice the owner.
select test.login(:alice, 'aal2', 'alice@acme.test');
set role authenticated;
insert into public.risks (org_id, display_id, data) values
  (:'acme', 'R-060', '{"title":"Exception one"}'), (:'acme', 'R-061', '{"title":"Exception two"}'),
  (:'acme', 'R-062', '{"title":"Exception three"}'), (:'acme', 'R-063', '{"title":"Exception four"}');
reset role;

-- A viewer cannot request. An analyst can, with a reason and a future date within two years.
select test.login(:dave, 'aal2', 'dave@acme.test');
set role authenticated;
select test.fails('a viewer cannot request an exception', format($$select public.request_exception(%L, 'R-060', 'Legacy system', current_date + 90)$$, :'acme'));
reset role;
select test.login(:carol, 'aal2', 'carol@acme.test');
set role authenticated;
select test.fails('a request needs a reason', format($$select public.request_exception(%L, 'R-060', '  ', current_date + 90)$$, :'acme'));
select test.fails('the expiry must be in the future', format($$select public.request_exception(%L, 'R-060', 'Legacy system', current_date)$$, :'acme'));
select test.fails('an exception lasts at most two years', format($$select public.request_exception(%L, 'R-060', 'Legacy system', current_date + 731)$$, :'acme'));
select test.fails('the risk must exist', format($$select public.request_exception(%L, 'R-999', 'Legacy system', current_date + 90)$$, :'acme'));
select public.request_exception(:'acme', 'R-060', 'Legacy system cannot be patched', current_date + 90) as req60 \gset
select test.ok('an analyst can request an exception', (select status from public.risk_exceptions where id = :'req60') = 'requested');
select test.ok('a request marks the risk as an exception awaiting approval',
  (select data ->> 'logException' = 'Yes' and data ->> 'exceptionPending' = to_char(current_date, 'YYYY-MM-DD') and not (data ? 'exceptionApproved') from public.risks where display_id = 'R-060'));
select test.fails('a risk has one open request at a time', format($$select public.request_exception(%L, 'R-060', 'Again', current_date + 90)$$, :'acme'));
select test.fails('an analyst cannot decide a request', format($$select public.decide_exception(%L, %L, true, '')$$, :'acme', :'req60'));

-- The approval fields cannot be set by writing the risk, however it is written.
update public.risks set data = data || '{"exceptionApproved":"Yes","exceptionExpiry":"2099-01-01","exceptionApprovedBy":"carol@acme.test","exceptionApprovedDate":"2026-01-01"}' where display_id = 'R-060';
select test.ok('writing the approval fields on a risk has no effect',
  (select not (data ? 'exceptionApproved') and not (data ? 'exceptionExpiry') and not (data ? 'exceptionApprovedBy') and data ->> 'exceptionPending' is not null from public.risks where display_id = 'R-060'));
update public.risks set data = (data - 'exceptionPending') where display_id = 'R-060';
select test.ok('the pending mark cannot be cleared by writing the risk', (select data ? 'exceptionPending' from public.risks where display_id = 'R-060'));
insert into public.risks (org_id, display_id, data) values (:'acme', 'R-064', '{"title":"Imported","exceptionApproved":"Yes","exceptionExpiry":"2099-01-01","exceptionPending":"2026-01-01"}');
select test.ok('a new risk cannot arrive already approved', (select not (data ? 'exceptionApproved') and not (data ? 'exceptionExpiry') and not (data ? 'exceptionPending') from public.risks where display_id = 'R-064'));
update public.risks set data = data || '{"title":"Exception one, edited"}' where display_id = 'R-060';
select test.ok('other changes to the risk still save', (select data ->> 'title' from public.risks where display_id = 'R-060') = 'Exception one, edited');
reset role;
update public.risks set data = data || '{"exceptionApprovedBy":"owner"}' where display_id = 'R-064';
select test.ok('the database owner can still change the approval fields (the functions rely on it)', (select data ->> 'exceptionApprovedBy' from public.risks where display_id = 'R-064') = 'owner');

-- Anyone who can read the risk can read its requests; other workspaces and sessions without MFA cannot.
select test.login(:dave, 'aal2', 'dave@acme.test');
set role authenticated;
select test.ok('a viewer can read the requests on a risk', test.count($$select 1 from public.risk_exceptions where risk_ref = 'R-060'$$) = 1);
select test.fails('nobody can write requests directly', format($$insert into public.risk_exceptions (org_id, risk_ref, reason, proposed_expiry, requested_by, requested_by_email) values (%L, 'R-061', 'x', current_date + 5, %L, 'x')$$, :'acme', :dave));
select test.fails('a request cannot be edited directly', $$update public.risk_exceptions set status = 'approved'$$);
select test.fails('a request cannot be deleted directly', $$delete from public.risk_exceptions$$);
reset role;
select test.login(:bob, 'aal2', 'bob@other.test');
set role authenticated;
select test.ok('tenant isolation: Bob cannot read Acme''s exception requests', test.count($$select 1 from public.risk_exceptions$$) = 0);
select test.fails('tenant isolation: Bob cannot request an exception on Acme''s risk', format($$select public.request_exception(%L, 'R-061', 'x', current_date + 5)$$, :'acme'));
select test.fails('tenant isolation: Bob cannot decide Acme''s request', format($$select public.decide_exception(%L, %L, true, '')$$, :'acme', :'req60'));
reset role;
select test.login(:alice, 'aal1', 'alice@acme.test');
set role authenticated;
select test.ok('a session without MFA cannot read requests', test.count($$select 1 from public.risk_exceptions$$) = 0);
select test.fails('a session without MFA cannot decide', format($$select public.decide_exception(%L, %L, true, '')$$, :'acme', :'req60'));
reset role;
select test.ok('anonymous callers cannot run the exception functions', not has_function_privilege('anon', 'public.request_exception(uuid, text, text, date)', 'execute')
  and not has_function_privilege('anon', 'public.decide_exception(uuid, uuid, boolean, text)', 'execute')
  and not has_function_privilege('anon', 'public.withdraw_exception(uuid, uuid)', 'execute')
  and not has_function_privilege('anon', 'public.revoke_exception(uuid, text, text)', 'execute')
  and not has_table_privilege('anon', 'public.risk_exceptions', 'select'));

-- The approver role: an analyst's rights plus approving, below admin. Dave is made an approver.
update public.memberships set role = 'approver' where org_id = :'acme' and user_id = :dave;
select test.login(:dave, 'aal2', 'dave@acme.test');
set role authenticated;
select test.ok('an approver can add risks, like an analyst', test.affected(format($$insert into public.risks (org_id, display_id, data) values (%L, 'R-065', '{"title":"By an approver"}')$$, :'acme')) = 1);
select test.fails('an approver cannot invite members', format($$select public.invite_member(%L, 'someone@acme.test', 'viewer')$$, :'acme'));
select test.fails('an approver cannot change roles', format($$select public.set_member_role(%L, %L, 'viewer')$$, :'acme', :carol));
select test.ok('an approver cannot read the audit log', test.count($$select 1 from public.audit_log$$) = 0);
select public.decide_exception(:'acme', :'req60', true, 'Compensating control in place');
select test.ok('an approver can approve: the risk shows who, when and until when',
  (select data ->> 'exceptionApproved' = 'Yes' and data ->> 'exceptionExpiry' = to_char(current_date + 90, 'YYYY-MM-DD') and data ->> 'exceptionApprovedBy' = 'dave@acme.test'
    and data ->> 'exceptionApprovedDate' = to_char(current_date, 'YYYY-MM-DD') and not (data ? 'exceptionPending') from public.risks where display_id = 'R-060'));
select test.ok('the request records the decision', (select status = 'approved' and decided_by_email = 'dave@acme.test' and decision_note = 'Compensating control in place' from public.risk_exceptions where id = :'req60'));
select test.fails('a request can only be decided once', format($$select public.decide_exception(%L, %L, false, 'changed my mind')$$, :'acme', :'req60'));
reset role;

-- Nobody decides their own request, whatever their role.
select test.login(:dave, 'aal2', 'dave@acme.test');
set role authenticated;
select public.request_exception(:'acme', 'R-061', 'Vendor cannot upgrade', current_date + 60) as req61 \gset
select test.fails('an approver cannot decide a request they made', format($$select public.decide_exception(%L, %L, true, '')$$, :'acme', :'req61'));
reset role;
select test.login(:alice, 'aal2', 'alice@acme.test');
set role authenticated;
select public.request_exception(:'acme', 'R-062', 'Owner request', current_date + 30) as req62 \gset
select test.fails('an owner cannot decide a request they made', format($$select public.decide_exception(%L, %L, true, '')$$, :'acme', :'req62'));
reset role;
select test.login(:alice, 'aal2', 'alice@acme.test');
set role authenticated;
select public.decide_exception(:'acme', :'req61', true, '');
select test.ok('an owner can approve someone else''s request (admins and owners approve by rank)', (select data ->> 'exceptionApprovedBy' = 'alice@acme.test' from public.risks where display_id = 'R-061'));
reset role;

-- A rejection needs a note, and a rejected first request leaves the risk marked as not approved.
select test.login(:dave, 'aal2', 'dave@acme.test');
set role authenticated;
select test.fails('a rejection needs a reason', format($$select public.decide_exception(%L, %L, false, '')$$, :'acme', (select id from public.risk_exceptions where risk_ref = 'R-062' and status = 'requested')));
select public.decide_exception(:'acme', (select id from public.risk_exceptions where risk_ref = 'R-062' and status = 'requested'), false, 'Fix it instead');
select test.ok('a rejected first request marks the risk as not approved', (select data ->> 'exceptionApproved' = 'No' and not (data ? 'exceptionPending') from public.risks where display_id = 'R-062'));
reset role;

-- A renewal: the earlier approval stands while it waits, and a new approval replaces it.
select test.login(:carol, 'aal2', 'carol@acme.test');
set role authenticated;
select public.request_exception(:'acme', 'R-060', 'Still cannot be patched', current_date + 180) as renew60 \gset
select test.ok('a request on an approved exception is a renewal', (select renewal from public.risk_exceptions where id = :'renew60'));
select test.ok('the earlier approval stands while a renewal waits', (select data ->> 'exceptionApproved' = 'Yes' and data ->> 'exceptionExpiry' = to_char(current_date + 90, 'YYYY-MM-DD') and data ? 'exceptionPending' from public.risks where display_id = 'R-060'));
reset role;
select test.login(:dave, 'aal2', 'dave@acme.test');
set role authenticated;
select public.decide_exception(:'acme', :'renew60', false, 'Not renewed yet');
select test.ok('a rejected renewal leaves the earlier approval to run out', (select data ->> 'exceptionApproved' = 'Yes' and data ->> 'exceptionExpiry' = to_char(current_date + 90, 'YYYY-MM-DD') and not (data ? 'exceptionPending') from public.risks where display_id = 'R-060'));
reset role;
select test.login(:carol, 'aal2', 'carol@acme.test');
set role authenticated;
select public.request_exception(:'acme', 'R-060', 'Renewal, with the plan attached', current_date + 200) as renew60b \gset
reset role;
select test.login(:dave, 'aal2', 'dave@acme.test');
set role authenticated;
select public.decide_exception(:'acme', :'renew60b', true, '');
select test.ok('an approved renewal replaces the expiry', (select data ->> 'exceptionExpiry' = to_char(current_date + 200, 'YYYY-MM-DD') from public.risks where display_id = 'R-060'));
reset role;

-- Withdrawing: the requester, or an admin or owner; not another approver.
select test.login(:carol, 'aal2', 'carol@acme.test');
set role authenticated;
select public.request_exception(:'acme', 'R-063', 'Temporary', current_date + 30) as req63 \gset
reset role;
select test.login(:dave, 'aal2', 'dave@acme.test');
set role authenticated;
select test.fails('an approver cannot withdraw someone else''s request', format($$select public.withdraw_exception(%L, %L)$$, :'acme', :'req63'));
reset role;
select test.login(:carol, 'aal2', 'carol@acme.test');
set role authenticated;
select public.withdraw_exception(:'acme', :'req63');
select test.ok('the requester can withdraw a request: the risk has nothing pending', (select status = 'withdrawn' from public.risk_exceptions where id = :'req63')
  and (select not (data ? 'exceptionPending') from public.risks where display_id = 'R-063'));
select test.fails('a decided request cannot be withdrawn', format($$select public.withdraw_exception(%L, %L)$$, :'acme', :'req63'));
select public.request_exception(:'acme', 'R-063', 'Temporary again', current_date + 30) as req63b \gset
reset role;
select test.login(:alice, 'aal2', 'alice@acme.test');
set role authenticated;
select public.withdraw_exception(:'acme', :'req63b');
select test.ok('an owner can withdraw someone else''s request', (select status = 'withdrawn' from public.risk_exceptions where id = :'req63b'));
reset role;

-- Revoking an approved exception: approvers and above, with a note.
select test.login(:carol, 'aal2', 'carol@acme.test');
set role authenticated;
select test.fails('an analyst cannot revoke an exception', format($$select public.revoke_exception(%L, 'R-060', 'No longer needed')$$, :'acme'));
reset role;
select test.login(:dave, 'aal2', 'dave@acme.test');
set role authenticated;
select test.fails('revoking needs a reason', format($$select public.revoke_exception(%L, 'R-060', '')$$, :'acme'));
select test.fails('a risk with no approved exception cannot be revoked', format($$select public.revoke_exception(%L, 'R-062', 'x')$$, :'acme'));
select public.revoke_exception(:'acme', 'R-060', 'The system was replaced');
select test.ok('revoking clears the approval, who approved and the expiry', (select data ->> 'exceptionApproved' = 'No' and not (data ? 'exceptionExpiry') and not (data ? 'exceptionApprovedBy') and not (data ? 'exceptionApprovedDate') from public.risks where display_id = 'R-060'));
reset role;

-- Every step is audited, and the risk's history shows the approval fields that are key fields.
select test.ok('requests and decisions are audited', exists (select 1 from public.audit_log where entity = 'risk_exceptions' and entity_id = 'R-060' and action = 'insert')
  and exists (select 1 from public.audit_log where entity = 'risk_exceptions' and entity_id = 'R-060' and action = 'update' and details ->> 'status' = 'approved'));
select test.ok('revoking is audited with its note', exists (select 1 from public.audit_log where entity = 'risk_exceptions' and entity_id = 'R-060' and action = 'revoke' and details ->> 'note' = 'The system was replaced'));
select test.ok('an approval is in the risk''s audit trail as a change to the risk', exists (select 1 from public.audit_log where entity = 'risks' and entity_id = 'R-060' and action = 'update' and details -> 'changes' -> 'exceptionApproved' ->> 'to' = 'Yes' and actor_email = 'dave@acme.test'));

-- Owners and admins manage approvers like analysts: only owners can manage admins.
select test.login(:alice, 'aal2', 'alice@acme.test');
set role authenticated;
select test.ok('an owner can invite an approver', (select public.invite_member(:'acme', 'newapprover@acme.test', 'approver') is not null));
select test.ok('the invitation keeps the approver role', (select role = 'approver' from public.invitations where email = 'newapprover@acme.test'));
reset role;
update public.memberships set role = 'admin' where org_id = :'acme' and user_id = :carol;
select test.login(:carol, 'aal2', 'carol@acme.test');
set role authenticated;
select public.set_member_role(:'acme', :dave, 'viewer');
select test.ok('an admin can make an approver a viewer', (select role from public.memberships where org_id = :'acme' and user_id = :dave) = 'viewer');
select public.set_member_role(:'acme', :dave, 'approver');
select test.ok('an admin can make a viewer an approver', (select role from public.memberships where org_id = :'acme' and user_id = :dave) = 'approver');
select test.ok('an admin can invite an approver', (select public.invite_member(:'acme', 'another@acme.test', 'approver') is not null));
select test.fails('an admin cannot make anyone an admin', format($$select public.set_member_role(%L, %L, 'admin')$$, :'acme', :dave));
reset role;
update public.memberships set role = 'analyst' where org_id = :'acme' and user_id = :carol;

-- A deleted risk takes its requests with it.
select test.login(:alice, 'aal2', 'alice@acme.test');
set role authenticated;
delete from public.risks where display_id = 'R-060';
reset role;
select test.ok('deleting a risk removes its exception requests', not exists (select 1 from public.risk_exceptions where risk_ref = 'R-060'));

-- ---- Deleting a workspace ----
-- A throwaway workspace with a risk and a second member, so the cascade has something to remove.
select test.login(:alice, 'aal2', 'alice@acme.test');
set role authenticated;
select public.create_organization('Doomed Co', 'csf2') as doomed \gset
insert into public.risks (org_id, display_id, data) values (:'doomed', 'R-001', '{"title":"To be deleted"}');
reset role;
insert into public.memberships (org_id, user_id, role, email) values (:'doomed', :carol, 'analyst', 'carol@acme.test');

select test.login(:carol, 'aal2', 'carol@acme.test');
set role authenticated;
select test.fails('an analyst cannot delete the workspace', format($$select public.delete_workspace(%L, 'Doomed Co')$$, :'doomed'));
reset role;
select test.login(:bob, 'aal2', 'bob@other.test');
set role authenticated;
select test.fails('a non-member cannot delete the workspace', format($$select public.delete_workspace(%L, 'Doomed Co')$$, :'doomed'));
reset role;

select test.login(:alice, 'aal1', 'alice@acme.test');
set role authenticated;
select test.fails('an owner without MFA cannot delete the workspace', format($$select public.delete_workspace(%L, 'Doomed Co')$$, :'doomed'));
reset role;

select test.login(:alice, 'aal2', 'alice@acme.test');
set role authenticated;
select test.fails('deleting a workspace needs its exact name', format($$select public.delete_workspace(%L, 'Wrong Name')$$, :'doomed'));
select test.fails('the workspace name is case sensitive', format($$select public.delete_workspace(%L, 'doomed co')$$, :'doomed'));
select test.fails('the workspace name cannot be left out', format($$select public.delete_workspace(%L, null)$$, :'doomed'));
select test.fails('deleting a workspace that does not exist fails', $$select public.delete_workspace('00000000-0000-0000-0000-0000000000ff', 'Doomed Co')$$);
reset role;
select test.ok('a refused deletion leaves the workspace and its records', exists (select 1 from public.organizations where id = :'doomed')
  and exists (select 1 from public.risks where org_id = :'doomed'));

set role authenticated;
select public.delete_workspace(:'doomed', 'Doomed Co');
reset role;
select test.ok('the owner can delete the workspace', not exists (select 1 from public.organizations where id = :'doomed'));
select test.ok('deleting the workspace deletes its records', not exists (select 1 from public.risks where org_id = :'doomed'));
select test.ok('deleting the workspace removes its members', not exists (select 1 from public.memberships where org_id = :'doomed'));
select test.ok('the audit log keeps a record of who deleted the workspace',
  exists (select 1 from public.audit_log where org_id = :'doomed' and action = 'delete' and entity = 'organizations' and actor_email = 'alice@acme.test' and details ->> 'name' = 'Doomed Co'));
select test.ok('the audit log keeps the workspace''s earlier records', exists (select 1 from public.audit_log where org_id = :'doomed' and entity = 'risks' and action = 'insert'));
select test.ok('deleting one workspace leaves the others', exists (select 1 from public.organizations where id = :'acme')
  and exists (select 1 from public.organizations where id = :'other'));
-- A table added later that holds workspace data must be deleted with the workspace, or deleting it would leave data behind.
select test.ok('every table holding workspace data is deleted with the workspace (only the audit log is kept)', not exists (
  select 1 from information_schema.columns c
  join information_schema.tables t on t.table_schema = c.table_schema and t.table_name = c.table_name and t.table_type = 'BASE TABLE'
  where c.table_schema = 'public' and c.column_name = 'org_id' and c.table_name <> 'audit_log'
    and not exists (
      select 1 from pg_constraint k
      where k.conrelid = format('public.%I', c.table_name)::regclass and k.contype = 'f'
        and k.confrelid = 'public.organizations'::regclass and k.confdeltype = 'c'
        and k.conkey = array[(select a.attnum from pg_attribute a where a.attrelid = k.conrelid and a.attname = 'org_id')]
    )
));
select test.ok('people can still sign in after their workspace is deleted', exists (select 1 from auth.users where id = :carol));
select test.fails('the audit log is still append-only after a workspace is deleted', $$delete from public.audit_log$$);

\set QUIET off
select case when ok then 'PASS' else 'FAIL' end as result, name, case when not ok then detail end as detail from test.results order by ok, name;
select count(*) filter (where ok) as passed, count(*) filter (where not ok) as failed from test.results;
