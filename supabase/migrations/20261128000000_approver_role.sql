-- A fifth role between analyst and admin: an approver does everything an analyst does and can also approve or reject
-- risk exceptions (see the exception approvals migration). Admins and owners can approve too, by rank. The value is added
-- here, on its own, because a new enum value can't be used in the transaction that adds it.
alter type public.member_role add value if not exists 'approver' before 'admin';
