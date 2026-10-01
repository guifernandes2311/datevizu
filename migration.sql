-- Datevizu — migração para um banco JÁ criado com o schema.sql antigo.
-- Rode no SQL Editor do Supabase (pode rodar mais de uma vez).

-- 1) Dono enxerga a própria agenda (corrige "Não foi possível criar a agenda")
drop policy if exists agendas_select_members on public.agendas;
create policy agendas_select_members on public.agendas for select
  using (public.is_member(id) or owner_id = auth.uid());

-- 2) Uma agenda por usuário, garantido no banco
create unique index if not exists agendas_one_per_owner on public.agendas (owner_id);

-- 3) CPF não legível/editável pela API
revoke select, update on public.profiles from anon, authenticated;
grant select (id, name, created_at) on public.profiles to authenticated;
grant update (name) on public.profiles to authenticated;

-- 4) Entrar em agenda só com código
create or replace function public.join_agenda(p_code text) returns uuid
language plpgsql security definer set search_path = public as $$
declare ag uuid;
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  select id into ag from public.agendas where upper(code) = upper(p_code);
  if ag is null then raise exception 'code_not_found'; end if;
  insert into public.agenda_members (agenda_id, user_id, role) values (ag, auth.uid(), 'p');
  return ag;
end;
$$;
revoke execute on function public.join_agenda(text) from public, anon;
grant execute on function public.join_agenda(text) to authenticated;
drop function if exists public.find_agenda_by_code(text);

create or replace function public.is_owner_of(_agenda_id uuid, _user_id uuid) returns boolean
language sql security definer stable set search_path = public as $$
  select exists(select 1 from public.agendas where id = _agenda_id and owner_id = _user_id);
$$;

-- 5) Policies de agenda_members: só o criador se insere como admin; criador não é rebaixado/removido
drop policy if exists members_insert_self on public.agenda_members;
drop policy if exists members_insert_owner on public.agenda_members;
create policy members_insert_owner on public.agenda_members for insert
  with check (user_id = auth.uid() and role = 'a' and public.is_owner_of(agenda_id, auth.uid()));

drop policy if exists members_update_admin on public.agenda_members;
create policy members_update_admin on public.agenda_members for update
  using (public.is_admin(agenda_id) and not public.is_owner_of(agenda_id, user_id))
  with check (public.is_admin(agenda_id) and not public.is_owner_of(agenda_id, user_id));

drop policy if exists members_delete_admin_or_self on public.agenda_members;
create policy members_delete_admin_or_self on public.agenda_members for delete
  using ((public.is_admin(agenda_id) or user_id = auth.uid()) and not public.is_owner_of(agenda_id, user_id));

-- 6) Visualização só em eventos de agendas das quais a pessoa participa
drop policy if exists views_insert_own on public.event_views;
create policy views_insert_own on public.event_views for insert
  with check (user_id = auth.uid() and public.is_member((select agenda_id from public.events e where e.id = event_id)));
