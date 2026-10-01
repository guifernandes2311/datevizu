-- Datevizu — schema do banco de dados (Supabase / Postgres)
-- Rode este arquivo inteiro no SQL Editor do seu projeto Supabase (Project > SQL Editor > New query).

create extension if not exists pgcrypto;

-- =========================================================
-- TABELAS
-- =========================================================

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  name text not null,
  cpf text unique,
  created_at timestamptz not null default now()
);

create table public.agendas (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  description text not null default '',
  code text not null unique,
  owner_id uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table public.agenda_members (
  agenda_id uuid not null references public.agendas(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  role text not null default 'p' check (role in ('a','p')),
  joined_at timestamptz not null default now(),
  primary key (agenda_id, user_id)
);

create table public.events (
  id uuid primary key default gen_random_uuid(),
  agenda_id uuid not null references public.agendas(id) on delete cascade,
  title text not null,
  date date not null,
  start_time text not null,
  end_time text not null,
  description text not null default '',
  note text not null default '',
  created_by uuid references public.profiles(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  last_changed_fields text[] not null default '{}',
  last_changed_by uuid references public.profiles(id),
  last_changed_at timestamptz
);

create table public.event_views (
  event_id uuid not null references public.events(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  viewed_at timestamptz not null default now(),
  primary key (event_id, user_id)
);

create table public.questions (
  id uuid primary key default gen_random_uuid(),
  event_id uuid not null references public.events(id) on delete cascade,
  agenda_id uuid not null references public.agendas(id) on delete cascade,
  user_id uuid not null references public.profiles(id),
  text text not null,
  created_at timestamptz not null default now(),
  answer_text text,
  answer_by uuid references public.profiles(id),
  answer_at timestamptz
);

create table public.notifications (
  id uuid primary key default gen_random_uuid(),
  agenda_id uuid not null references public.agendas(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  event_id uuid references public.events(id) on delete set null,
  text text not null,
  created_at timestamptz not null default now(),
  read boolean not null default false
);

create unique index agendas_one_per_owner on public.agendas (owner_id);
create index on public.agenda_members (user_id);
create index on public.events (agenda_id);
create index on public.questions (agenda_id);
create index on public.questions (event_id);
create index on public.notifications (user_id, read);
create index on public.event_views (event_id);

-- =========================================================
-- FUNÇÕES AUXILIARES (SECURITY DEFINER: rodam ignorando RLS)
-- =========================================================

create or replace function public.is_member(_agenda_id uuid) returns boolean
language sql security definer stable set search_path = public as $$
  select exists(select 1 from public.agenda_members where agenda_id = _agenda_id and user_id = auth.uid());
$$;

create or replace function public.is_admin(_agenda_id uuid) returns boolean
language sql security definer stable set search_path = public as $$
  select exists(select 1 from public.agenda_members where agenda_id = _agenda_id and user_id = auth.uid() and role = 'a');
$$;

-- Cria o perfil automaticamente quando alguém se cadastra (auth.users)
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if new.raw_user_meta_data->>'cpf' is not null
     and exists(select 1 from public.profiles where cpf = new.raw_user_meta_data->>'cpf') then
    raise exception 'cpf_duplicado';
  end if;
  insert into public.profiles (id, name, cpf)
  values (new.id, coalesce(new.raw_user_meta_data->>'name', new.email), new.raw_user_meta_data->>'cpf');
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- Entrar numa agenda com o código (único caminho para virar participante)
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

-- true se _user_id é o criador da agenda (usado nas policies de agenda_members)
create or replace function public.is_owner_of(_agenda_id uuid, _user_id uuid) returns boolean
language sql security definer stable set search_path = public as $$
  select exists(select 1 from public.agendas where id = _agenda_id and owner_id = _user_id);
$$;

-- =========================================================
-- NOTIFICAÇÕES AUTOMÁTICAS (triggers)
-- =========================================================

create or replace function public.trg_events_before_update() returns trigger
language plpgsql as $$
declare changed text[] := '{}';
begin
  if new.title is distinct from old.title then changed := changed || 'título'; end if;
  if new.date is distinct from old.date or new.start_time is distinct from old.start_time or new.end_time is distinct from old.end_time then
    changed := changed || 'data/horário';
  end if;
  if new.description is distinct from old.description then changed := changed || 'descrição'; end if;
  if new.note is distinct from old.note then changed := changed || 'observação'; end if;
  if array_length(changed,1) > 0 then
    new.last_changed_fields := changed;
    new.last_changed_by := auth.uid();
    new.last_changed_at := now();
  end if;
  new.updated_at := now();
  return new;
end;
$$;

drop trigger if exists events_before_update on public.events;
create trigger events_before_update before update on public.events
  for each row execute function public.trg_events_before_update();

create or replace function public.trg_events_after_write() returns trigger
language plpgsql security definer set search_path = public as $$
declare msg text; recipient uuid;
begin
  if tg_op = 'INSERT' then
    msg := 'Novo evento: ' || new.title;
    for recipient in select user_id from public.agenda_members where agenda_id = new.agenda_id and user_id <> auth.uid() loop
      insert into public.notifications(agenda_id,user_id,event_id,text) values (new.agenda_id, recipient, new.id, msg);
    end loop;
  elsif tg_op = 'UPDATE' and new.last_changed_at is not null and old.last_changed_at is distinct from new.last_changed_at then
    msg := 'Evento alterado: ' || new.title || ' (' || array_to_string(new.last_changed_fields, ', ') || ')';
    for recipient in select user_id from public.agenda_members where agenda_id = new.agenda_id and user_id <> auth.uid() loop
      insert into public.notifications(agenda_id,user_id,event_id,text) values (new.agenda_id, recipient, new.id, msg);
    end loop;
  end if;
  return new;
end;
$$;

drop trigger if exists events_after_write on public.events;
create trigger events_after_write after insert or update on public.events
  for each row execute function public.trg_events_after_write();

create or replace function public.trg_questions_after_insert() returns trigger
language plpgsql security definer set search_path = public as $$
declare msg text; recipient uuid; asker_name text; ev_title text;
begin
  select name into asker_name from public.profiles where id = new.user_id;
  select title into ev_title from public.events where id = new.event_id;
  msg := coalesce(asker_name,'Alguém') || ' perguntou em "' || ev_title || '"';
  for recipient in select user_id from public.agenda_members where agenda_id = new.agenda_id and role = 'a' and user_id <> new.user_id loop
    insert into public.notifications(agenda_id,user_id,event_id,text) values (new.agenda_id, recipient, new.event_id, msg);
  end loop;
  return new;
end;
$$;

drop trigger if exists questions_after_insert on public.questions;
create trigger questions_after_insert after insert on public.questions
  for each row execute function public.trg_questions_after_insert();

create or replace function public.trg_questions_after_update() returns trigger
language plpgsql security definer set search_path = public as $$
declare msg text; answerer_name text; ev_title text;
begin
  if old.answer_text is null and new.answer_text is not null then
    select name into answerer_name from public.profiles where id = new.answer_by;
    select title into ev_title from public.events where id = new.event_id;
    msg := coalesce(answerer_name,'Um administrador') || ' respondeu sua pergunta em "' || ev_title || '"';
    if new.user_id <> new.answer_by then
      insert into public.notifications(agenda_id,user_id,event_id,text) values (new.agenda_id, new.user_id, new.event_id, msg);
    end if;
  end if;
  return new;
end;
$$;

drop trigger if exists questions_after_update on public.questions;
create trigger questions_after_update after update on public.questions
  for each row execute function public.trg_questions_after_update();

create or replace function public.trg_members_after_insert() returns trigger
language plpgsql security definer set search_path = public as $$
declare msg text; recipient uuid; joiner_name text; ag_name text;
begin
  if new.role = 'p' then
    select name into joiner_name from public.profiles where id = new.user_id;
    select name into ag_name from public.agendas where id = new.agenda_id;
    msg := coalesce(joiner_name,'Alguém') || ' entrou na agenda "' || ag_name || '"';
    for recipient in select user_id from public.agenda_members where agenda_id = new.agenda_id and role = 'a' and user_id <> new.user_id loop
      insert into public.notifications(agenda_id,user_id,text) values (new.agenda_id, recipient, msg);
    end loop;
  end if;
  return new;
end;
$$;

drop trigger if exists members_after_insert on public.agenda_members;
create trigger members_after_insert after insert on public.agenda_members
  for each row execute function public.trg_members_after_insert();

create or replace function public.trg_members_after_update() returns trigger
language plpgsql security definer set search_path = public as $$
declare msg text; ag_name text;
begin
  if old.role is distinct from new.role then
    select name into ag_name from public.agendas where id = new.agenda_id;
    msg := 'Sua função em "' || ag_name || '" agora é ' || (case when new.role = 'a' then 'Administrador' else 'Participante' end);
    insert into public.notifications(agenda_id,user_id,text) values (new.agenda_id, new.user_id, msg);
  end if;
  return new;
end;
$$;

drop trigger if exists members_after_update on public.agenda_members;
create trigger members_after_update after update on public.agenda_members
  for each row execute function public.trg_members_after_update();

-- =========================================================
-- ROW LEVEL SECURITY
-- =========================================================

alter table public.profiles enable row level security;
alter table public.agendas enable row level security;
alter table public.agenda_members enable row level security;
alter table public.events enable row level security;
alter table public.event_views enable row level security;
alter table public.questions enable row level security;
alter table public.notifications enable row level security;

create policy profiles_select_authenticated on public.profiles for select
  using (auth.role() = 'authenticated');
create policy profiles_update_own on public.profiles for update
  using (auth.uid() = id) with check (auth.uid() = id);

-- CPF é dado sensível: ninguém lê/edita pela API (só id, name, created_at; o nome é editável).
-- O CPF do próprio usuário vem de auth.users.raw_user_meta_data (user_metadata no front).
revoke select, update on public.profiles from anon, authenticated;
grant select (id, name, created_at) on public.profiles to authenticated;
grant update (name) on public.profiles to authenticated;

create policy agendas_select_members on public.agendas for select
  using (public.is_member(id) or owner_id = auth.uid());
create policy agendas_insert_owner on public.agendas for insert
  with check (owner_id = auth.uid());
create policy agendas_update_admin on public.agendas for update
  using (public.is_admin(id)) with check (public.is_admin(id));
create policy agendas_delete_owner on public.agendas for delete
  using (owner_id = auth.uid());

create policy members_select_same_agenda on public.agenda_members for select
  using (public.is_member(agenda_id));
-- Só o criador entra direto (como admin); participantes entram via join_agenda(código)
create policy members_insert_owner on public.agenda_members for insert
  with check (user_id = auth.uid() and role = 'a' and public.is_owner_of(agenda_id, auth.uid()));
-- O criador não pode ser rebaixado nem removido
create policy members_update_admin on public.agenda_members for update
  using (public.is_admin(agenda_id) and not public.is_owner_of(agenda_id, user_id))
  with check (public.is_admin(agenda_id) and not public.is_owner_of(agenda_id, user_id));
create policy members_delete_admin_or_self on public.agenda_members for delete
  using ((public.is_admin(agenda_id) or user_id = auth.uid()) and not public.is_owner_of(agenda_id, user_id));

create policy events_select_members on public.events for select
  using (public.is_member(agenda_id));
create policy events_insert_admin on public.events for insert
  with check (public.is_admin(agenda_id));
create policy events_update_admin on public.events for update
  using (public.is_admin(agenda_id)) with check (public.is_admin(agenda_id));
create policy events_delete_admin on public.events for delete
  using (public.is_admin(agenda_id));

create policy views_select_own_or_admin on public.event_views for select
  using (user_id = auth.uid() or public.is_admin((select agenda_id from public.events e where e.id = event_id)));
create policy views_insert_own on public.event_views for insert
  with check (user_id = auth.uid() and public.is_member((select agenda_id from public.events e where e.id = event_id)));
create policy views_update_own on public.event_views for update
  using (user_id = auth.uid()) with check (user_id = auth.uid());

create policy questions_select_members on public.questions for select
  using (public.is_member(agenda_id));
create policy questions_insert_members on public.questions for insert
  with check (public.is_member(agenda_id) and user_id = auth.uid());
create policy questions_update_admin on public.questions for update
  using (public.is_admin(agenda_id)) with check (public.is_admin(agenda_id));

create policy notifications_select_own on public.notifications for select
  using (user_id = auth.uid());
create policy notifications_update_own on public.notifications for update
  using (user_id = auth.uid()) with check (user_id = auth.uid());

-- =========================================================
-- REALTIME (para atualizações ao vivo entre participantes)
-- =========================================================

alter publication supabase_realtime add table
  public.agendas, public.agenda_members, public.events, public.questions, public.notifications;
