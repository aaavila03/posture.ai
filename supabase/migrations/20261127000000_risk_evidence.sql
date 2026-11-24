-- Evidence files on a risk: a PDF, a text file or a PNG/JPEG image (a policy, an audit report, a screenshot), kept in the
-- database as base64 text, like the vendors' documents. Anyone who can read the risks can read and download them; analysts
-- and up add and remove them. Each file is at most 5 MB, a risk has at most 10, and a file's name is unique within its risk.
--
-- The database does the checking, so it holds whatever the client does: the data must be valid base64, it must start the
-- way its declared type does (so a web page can't be stored as an image), and the size is worked out from the data rather
-- than taken from the client. There is no update: to replace a file, remove it and add the new one. A file is removed with
-- its risk, so it can't turn up on a new risk that is given the same number. The workspace's deletion removes all of them.
create table public.risk_evidence (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id) on delete cascade,
  risk_ref text not null check (risk_ref ~ '^R-[0-9]{3,6}$'),
  name text not null check (char_length(name) between 1 and 200),
  media_type text not null check (media_type in ('application/pdf', 'text/plain', 'image/png', 'image/jpeg')),
  size integer not null check (size between 1 and 5242880),
  data text not null check (char_length(data) <= 7200000),
  created_at timestamptz not null default now(),
  created_by uuid,
  unique (org_id, risk_ref, name)
);
create index risk_evidence_risk_idx on public.risk_evidence (org_id, risk_ref);

alter table public.risk_evidence enable row level security;
create policy risk_evidence_select on public.risk_evidence for select to authenticated using (private.has_role(org_id, 'viewer'));
create policy risk_evidence_insert on public.risk_evidence for insert to authenticated with check (private.has_role(org_id, 'analyst'));
create policy risk_evidence_delete on public.risk_evidence for delete to authenticated using (private.has_role(org_id, 'analyst'));

revoke all on public.risk_evidence from anon, authenticated;
grant select, delete on public.risk_evidence to authenticated;
grant insert (org_id, risk_ref, name, media_type, size, data) on public.risk_evidence to authenticated;

-- Checks a new file and stamps who added it and when.
create or replace function private.risk_evidence_check()
returns trigger language plpgsql set search_path = '' as $$
declare
  bytes bytea;
begin
  if not exists (select 1 from public.risks r where r.org_id = new.org_id and r.display_id = new.risk_ref) then
    raise exception 'that risk does not exist';
  end if;
  if (select count(*) from public.risk_evidence e where e.org_id = new.org_id and e.risk_ref = new.risk_ref) >= 10 then
    raise exception 'a risk can have at most 10 evidence files';
  end if;
  if new.data !~ '^[A-Za-z0-9+/]+={0,2}$' then
    raise exception 'the file is not valid base64';
  end if;
  bytes := decode(new.data, 'base64');
  if not (case new.media_type
    when 'application/pdf' then left(new.data, 6) = 'JVBERi'
    when 'image/png' then left(new.data, 11) = 'iVBORw0KGgo'
    when 'image/jpeg' then left(new.data, 4) = '/9j/'
    else position('\x00'::bytea in bytes) = 0
  end) then
    raise exception 'the file is not what its type says it is';
  end if;
  new.size := octet_length(bytes);
  new.created_by := auth.uid();
  new.created_at := now();
  return new;
end $$;
create trigger risk_evidence_check before insert on public.risk_evidence
  for each row execute function private.risk_evidence_check();

-- Adding and removing a file are audited against the risk (the file's content is not).
create or replace function private.risk_evidence_audit()
returns trigger language plpgsql security definer set search_path = '' as $$
declare
  rec public.risk_evidence := coalesce(new, old);
begin
  perform private.write_audit(rec.org_id, lower(tg_op), 'risk_evidence', rec.risk_ref,
    jsonb_build_object('name', rec.name, 'size', rec.size, 'media_type', rec.media_type));
  return coalesce(new, old);
end $$;
create trigger risk_evidence_audit after insert or delete on public.risk_evidence
  for each row execute function private.risk_evidence_audit();

-- A deleted risk takes its evidence with it.
create or replace function private.risk_evidence_cleanup()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  delete from public.risk_evidence e where e.org_id = old.org_id and e.risk_ref = old.display_id;
  return old;
end $$;
create trigger risks_evidence_cleanup after delete on public.risks
  for each row execute function private.risk_evidence_cleanup();
