-- Viewers work only with risks: vendor records, vendors' questionnaire responses and
-- documents, and the executive briefing (which summarises vendors) are readable by
-- analysts and above. The app hides the Vendors and AI analyst tabs from viewers to match.

drop policy vendor_select on public.vendors;
create policy vendor_select on public.vendors for select to authenticated using (private.has_role(org_id, 'analyst'));

drop policy intake_response_select on public.intake_responses;
create policy intake_response_select on public.intake_responses for select to authenticated using (private.has_role(org_id, 'analyst'));

drop policy intake_document_select on public.intake_documents;
create policy intake_document_select on public.intake_documents for select to authenticated using (private.has_role(org_id, 'analyst'));

drop policy briefing_select on public.briefings;
create policy briefing_select on public.briefings for select to authenticated using (private.has_role(org_id, 'analyst'));
