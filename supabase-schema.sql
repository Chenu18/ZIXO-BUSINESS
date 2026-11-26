-- ZIXO Supabase database setup
-- Run this whole file in Supabase Dashboard > SQL Editor.
create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  role text not null default 'seller' check (role in ('owner','seller')),
  display_name text not null default 'ZIXO Seller',
  phone text,
  whatsapp text,
  facebook text,
  created_at timestamptz not null default now()
);

create table if not exists public.products (
  id uuid primary key default gen_random_uuid(),
  seller_id uuid not null references public.profiles(id) on delete cascade,
  title text not null,
  description text default '',
  category text default 'Account',
  price numeric(12,2) not null default 0 check (price >= 0),
  status text not null default 'available' check (status in ('available','sold')),
  image_urls text[] not null default '{}',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.reviews (
  id uuid primary key default gen_random_uuid(),
  customer_name text not null,
  rating integer not null check (rating between 1 and 5),
  comment text not null,
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  created_at timestamptz not null default now()
);

create table if not exists public.site_settings (
  id integer primary key check (id = 1),
  owner_name text default '',
  owner_phone text default '',
  owner_whatsapp text default '',
  footer_text text default 'ZIXO • Account catalogue'
);
insert into public.site_settings(id) values(1) on conflict(id) do nothing;

-- Create a profile automatically for each newly-created Auth user.
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles(id, display_name, role)
  values(new.id, coalesce(new.raw_user_meta_data->>'display_name','ZIXO Seller'), 'seller')
  on conflict(id) do nothing;
  return new;
end;
$$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
for each row execute procedure public.handle_new_user();

alter table public.profiles enable row level security;
alter table public.products enable row level security;
alter table public.reviews enable row level security;
alter table public.site_settings enable row level security;

-- Explicit API permissions. A seller must never be able to change their role.
grant select on public.profiles to anon, authenticated;
revoke update on public.profiles from authenticated;
grant update(display_name, phone, whatsapp, facebook) on public.profiles to authenticated;
grant select on public.products to anon, authenticated;
grant insert, update, delete on public.products to authenticated;
grant select, insert on public.reviews to anon, authenticated;
grant update, delete on public.reviews to authenticated;
grant select on public.site_settings to anon, authenticated;
grant insert, update, delete on public.site_settings to authenticated;

create or replace function public.is_owner()
returns boolean language sql stable security definer set search_path = public as $$
  select exists(select 1 from public.profiles where id = auth.uid() and role = 'owner');
$$;

-- Profiles are public only for displaying seller contact information.
drop policy if exists "profiles public read" on public.profiles;
create policy "profiles public read" on public.profiles for select using (true);
drop policy if exists "profile owner update own contact" on public.profiles;
create policy "profile owner update own contact" on public.profiles
for update using (id = auth.uid() or public.is_owner())
with check (id = auth.uid() or public.is_owner());

-- Sellers can only modify their own listings; owner can modify all listings.
drop policy if exists "products public read" on public.products;
create policy "products public read" on public.products for select using (true);
drop policy if exists "products insert own" on public.products;
create policy "products insert own" on public.products for insert
with check (seller_id = auth.uid() or public.is_owner());
drop policy if exists "products update own or owner" on public.products;
create policy "products update own or owner" on public.products for update
using (seller_id = auth.uid() or public.is_owner())
with check (seller_id = auth.uid() or public.is_owner());
drop policy if exists "products delete own or owner" on public.products;
create policy "products delete own or owner" on public.products for delete
using (seller_id = auth.uid() or public.is_owner());

-- Anyone can submit feedback, but only owner can view pending/rejected or moderate.
drop policy if exists "public submit reviews" on public.reviews;
create policy "public submit reviews" on public.reviews for insert
with check (status = 'pending');
drop policy if exists "public read approved reviews" on public.reviews;
create policy "public read approved reviews" on public.reviews for select
using (status = 'approved' or public.is_owner());
drop policy if exists "owner moderate reviews" on public.reviews;
create policy "owner moderate reviews" on public.reviews for update
using (public.is_owner()) with check (public.is_owner());
drop policy if exists "owner delete reviews" on public.reviews;
create policy "owner delete reviews" on public.reviews for delete
using (public.is_owner());

drop policy if exists "settings public read" on public.site_settings;
create policy "settings public read" on public.site_settings for select using (true);
drop policy if exists "owner settings update" on public.site_settings;
create policy "owner settings update" on public.site_settings for all
using (public.is_owner()) with check (public.is_owner());

-- Storage bucket for listing photos. Public can view photos; signed-in users
-- can upload under a folder named with their own auth user UUID.
insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
values('product-images','product-images',true,5242880,array['image/jpeg','image/png','image/webp'])
on conflict(id) do update set public=true, file_size_limit=5242880,
allowed_mime_types=array['image/jpeg','image/png','image/webp'];

drop policy if exists "public view product images" on storage.objects;
create policy "public view product images" on storage.objects for select
using (bucket_id = 'product-images');
drop policy if exists "seller upload own product images" on storage.objects;
create policy "seller upload own product images" on storage.objects for insert
to authenticated with check (
  bucket_id = 'product-images' and (storage.foldername(name))[1] = auth.uid()::text
);
drop policy if exists "seller delete own product images" on storage.objects;
create policy "seller delete own product images" on storage.objects for delete
to authenticated using (
  bucket_id = 'product-images' and ((storage.foldername(name))[1] = auth.uid()::text or public.is_owner())
);

-- After creating your owner login in Authentication > Users, run:
-- update public.profiles set role='owner', display_name='YOUR OWNER DISPLAY NAME'
-- where id=(select id from auth.users where email='YOUR_OWNER_EMAIL');
-- Create the seller login in Authentication > Users. Its profile defaults to role='seller'.
