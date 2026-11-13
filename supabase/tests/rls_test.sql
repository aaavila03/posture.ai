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

\set QUIET off
select case when ok then 'PASS' else 'FAIL' end as result, name, case when not ok then detail end as detail from test.results order by ok, name;
select count(*) filter (where ok) as passed, count(*) filter (where not ok) as failed from test.results;
