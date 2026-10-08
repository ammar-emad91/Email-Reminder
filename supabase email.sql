-- ============================================================
-- مصرف آسيا العراق الإسلامي - إعداد قاعدة البيانات
-- الصق هذا الملف كاملاً في Supabase > SQL Editor ثم اضغط Run
-- (غيّر اسم وكلمة سر الأدمن في الأسفل قبل التشغيل)
-- ============================================================

create extension if not exists pgcrypto with schema extensions;

create table if not exists app_users(
  username  text primary key,
  pass_hash text not null,
  role      text not null default 'user' check (role in ('admin','user'))
);
create table if not exists app_headers(
  id int primary key default 1,
  headers jsonb not null
);
create table if not exists app_rows(
  id   text primary key,
  data jsonb not null,
  ord  bigint not null default 0
);

-- منع أي وصول مباشر للجداول (الوصول فقط عبر الدوال أدناه)
alter table app_users   enable row level security;
alter table app_headers enable row level security;
alter table app_rows    enable row level security;

-- تسجيل الدخول: يرجع الصلاحية أو null
create or replace function app_login(u text, p text) returns text
language sql security definer set search_path = public, extensions as $$
  select role from app_users
  where username = u and pass_hash = extensions.crypt(p, pass_hash)
$$;

-- جلب كل البيانات المشتركة
create or replace function app_get(u text, p text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare r text;
begin
  r := app_login(u, p);
  if r is null then return null; end if;
  return jsonb_build_object(
    'role', r,
    'headers', (select headers from app_headers where id = 1),
    'rows', coalesce((select jsonb_agg(data order by ord) from app_rows), '[]'::jsonb)
  );
end $$;

-- حفظ/تعديل سطر (أي مستخدم)
create or replace function app_save_row(u text, p text, rid text, d jsonb, o bigint) returns boolean
language plpgsql security definer set search_path = public, extensions as $$
begin
  if app_login(u, p) is null then raise exception 'unauthorized'; end if;
  insert into app_rows(id, data, ord) values (rid, d, o)
  on conflict (id) do update set data = excluded.data;
  return true;
end $$;

-- حذف سطر (الأدمن فقط)
create or replace function app_delete_row(u text, p text, rid text) returns boolean
language plpgsql security definer set search_path = public, extensions as $$
begin
  if coalesce(app_login(u, p), '') <> 'admin' then raise exception 'forbidden'; end if;
  delete from app_rows where id = rid;
  return true;
end $$;

-- تعديل عناوين الأعمدة (الأدمن فقط)
create or replace function app_save_headers(u text, p text, h jsonb) returns boolean
language plpgsql security definer set search_path = public, extensions as $$
begin
  if coalesce(app_login(u, p), '') <> 'admin' then raise exception 'forbidden'; end if;
  insert into app_headers(id, headers) values (1, h)
  on conflict (id) do update set headers = excluded.headers;
  return true;
end $$;

-- إدارة الحسابات (الأدمن فقط)
create or replace function app_users_list(u text, p text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
begin
  if coalesce(app_login(u, p), '') <> 'admin' then raise exception 'forbidden'; end if;
  return coalesce((select jsonb_agg(jsonb_build_object('username', username, 'role', role) order by username) from app_users), '[]'::jsonb);
end $$;

create or replace function app_user_add(u text, p text, nu text, np text, nr text) returns boolean
language plpgsql security definer set search_path = public, extensions as $$
begin
  if coalesce(app_login(u, p), '') <> 'admin' then raise exception 'forbidden'; end if;
  if nr not in ('admin', 'user') then raise exception 'bad role'; end if;
  if length(trim(nu)) < 2 or length(np) < 4 then raise exception 'weak'; end if;
  if nu = u and nr <> 'admin' then raise exception 'cannot demote self'; end if;
  insert into app_users(username, pass_hash, role)
  values (trim(nu), extensions.crypt(np, extensions.gen_salt('bf')), nr)
  on conflict (username) do update set pass_hash = excluded.pass_hash, role = excluded.role;
  return true;
end $$;

create or replace function app_user_del(u text, p text, nu text) returns boolean
language plpgsql security definer set search_path = public, extensions as $$
begin
  if coalesce(app_login(u, p), '') <> 'admin' then raise exception 'forbidden'; end if;
  if nu = u then raise exception 'cannot delete self'; end if;
  delete from app_users where username = nu;
  return true;
end $$;

-- ============================================================
-- بيانات البداية
-- ============================================================
insert into app_headers(id, headers) values (1,
  '["الوقت والتاريخ","رقم الكتاب","الجهة","الموضوع","ملاحظات","المنبه","ملاحظات إضافية","اكتمال"]'::jsonb)
on conflict (id) do nothing;

-- !!! غيّر 'admin' وكلمة السر قبل التشغيل !!!
insert into app_users(username, pass_hash, role)
values ('admin', extensions.crypt('ضع_رمز_الادمن_هنا', extensions.gen_salt('bf')), 'admin')
on conflict (username) do nothing;
