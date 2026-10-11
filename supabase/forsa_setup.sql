-- ============================================================
-- Forsa V1 database schema (Supabase / Postgres)
-- Run once in the Supabase SQL editor.
-- ============================================================

-- ---------- Profiles (one row per user) ----------
create table if not exists public.profiles (
  id               uuid primary key references auth.users(id) on delete cascade,
  email            text,
  full_name        text not null default '',
  phone            text,
  city             text,
  user_type        text,            -- student, employee, extra_income, other
  university       text,
  role             text not null default 'seller' check (role in ('seller','admin')),
  trial_started_at timestamptz not null default now(),
  goal_waived      boolean not null default false,   -- paid EGP 100 to skip the 3-order goal
  paid_until       timestamptz,                       -- end of the paid subscription period
  created_at       timestamptz not null default now()
);

-- ---------- Products ----------
create table if not exists public.products (
  id              uuid primary key default gen_random_uuid(),
  name_en         text not null,
  name_ar         text not null,
  description_en  text default '',
  description_ar  text default '',
  category        text not null default 'Other',
  factory_code    text not null,            -- e.g. FT-104 (real factory name is never stored here)
  region          text default '',
  quality_score   numeric(2,1) default 4.5,
  wholesale_price integer not null check (wholesale_price > 0),
  min_price       integer not null,
  suggested_price integer not null,
  ship_days       integer not null default 3,
  image_url       text,
  stock           integer not null default 0,
  active          boolean not null default true,
  created_at      timestamptz not null default now(),
  check (min_price >= wholesale_price),
  check (suggested_price >= min_price)
);

-- ---------- Orders ----------
create table if not exists public.orders (
  id              uuid primary key default gen_random_uuid(),
  order_no        bigint generated always as identity,
  seller_id       uuid not null references public.profiles(id) on delete cascade,
  product_id      uuid not null references public.products(id),
  quantity        integer not null default 1 check (quantity between 1 and 20),
  unit_price      integer not null,        -- seller's selling price per item
  wholesale_price integer not null,        -- copied from the product when the order is created
  customer_name   text not null,
  customer_phone  text not null,
  governorate     text not null,
  address         text not null,
  notes           text default '',
  status          text not null default 'pending'
                  check (status in ('pending','confirmed','shipped','delivered','returned','cancelled')),
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now()
);
create index if not exists orders_seller_idx on public.orders(seller_id, created_at desc);

-- ---------- Payouts (weekly payments to sellers) ----------
create table if not exists public.payouts (
  id          uuid primary key default gen_random_uuid(),
  seller_id   uuid not null references public.profiles(id) on delete cascade,
  amount      integer not null check (amount > 0),
  method      text not null default 'instapay',
  reference   text default '',
  note        text default '',
  paid_at     timestamptz not null default now()
);

-- ---------- Subscription payments ----------
create table if not exists public.subscription_payments (
  id          uuid primary key default gen_random_uuid(),
  seller_id   uuid not null references public.profiles(id) on delete cascade,
  amount      integer not null default 100,
  months      integer not null default 1 check (months between 1 and 12),
  method      text not null check (method in ('instapay','vodafone_cash')),
  reference   text not null,
  status      text not null default 'pending' check (status in ('pending','approved','rejected')),
  created_at  timestamptz not null default now(),
  reviewed_at timestamptz
);

-- ---------- Submitted ideas ----------
create table if not exists public.ideas (
  id              uuid primary key default gen_random_uuid(),
  user_id         uuid not null references public.profiles(id) on delete cascade,
  title           text not null,
  problem         text not null,
  sector          text not null,
  stage           text not null check (stage in ('idea','prototype','selling')),
  funding_needed  integer default 0,
  status          text not null default 'new' check (status in ('new','reviewing','matched','declined')),
  created_at      timestamptz not null default now()
);

-- ============================================================
-- Helper functions
-- ============================================================
create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin');
$$;

-- A seller may create orders during the free first month, or while their subscription is paid.
create or replace function public.can_sell(uid uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.profiles p
    where p.id = uid
      and (now() < p.trial_started_at + interval '30 days'
           or (p.paid_until is not null and now() < p.paid_until))
  );
$$;

-- Create a profile automatically when someone signs up.
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, email, full_name, phone, city, user_type, university)
  values (
    new.id, new.email,
    coalesce(new.raw_user_meta_data->>'full_name', ''),
    new.raw_user_meta_data->>'phone',
    new.raw_user_meta_data->>'city',
    new.raw_user_meta_data->>'user_type',
    new.raw_user_meta_data->>'university'
  );
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- Sellers can edit their name/phone/city but never their role or plan fields.
create or replace function public.protect_profile_fields() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then
    new.role := old.role;
    new.trial_started_at := old.trial_started_at;
    new.goal_waived := old.goal_waived;
    new.paid_until := old.paid_until;
    new.email := old.email;
  end if;
  return new;
end $$;
drop trigger if exists profiles_protect on public.profiles;
create trigger profiles_protect before update on public.profiles
  for each row execute function public.protect_profile_fields();

-- On new orders: copy the wholesale price, enforce the minimum price, force status 'pending'.
create or replace function public.prepare_order() returns trigger
language plpgsql security definer set search_path = public as $$
declare p public.products;
begin
  select * into p from public.products where id = new.product_id and active;
  if not found then raise exception 'This product is not available'; end if;
  if new.unit_price < p.min_price then
    raise exception 'Selling price must be at least EGP %', p.min_price;
  end if;
  new.wholesale_price := p.wholesale_price;
  if not public.is_admin() then new.status := 'pending'; end if;
  return new;
end $$;
drop trigger if exists orders_prepare on public.orders;
create trigger orders_prepare before insert on public.orders
  for each row execute function public.prepare_order();

-- Sellers may only cancel their own pending orders; only admins change other fields.
create or replace function public.guard_order_update() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  new.updated_at := now();
  if public.is_admin() then return new; end if;
  if old.status = 'pending' and new.status = 'cancelled' then
    new.unit_price := old.unit_price; new.quantity := old.quantity;
    new.wholesale_price := old.wholesale_price; new.product_id := old.product_id;
    new.seller_id := old.seller_id;
    return new;
  end if;
  raise exception 'Only pending orders can be cancelled';
end $$;
drop trigger if exists orders_guard on public.orders;
create trigger orders_guard before update on public.orders
  for each row execute function public.guard_order_update();

-- When the admin approves a subscription payment, extend the seller's paid period.
create or replace function public.apply_subscription() returns trigger
language plpgsql security definer set search_path = public as $$
declare start_from timestamptz;
begin
  if new.status = 'approved' and old.status <> 'approved' then
    select greatest(coalesce(paid_until, now()), now()) into start_from
      from public.profiles where id = new.seller_id;
    update public.profiles
       set paid_until = start_from + (new.months * interval '30 days'),
           goal_waived = true
     where id = new.seller_id;
    new.reviewed_at := now();
  elsif new.status = 'rejected' and old.status <> 'rejected' then
    new.reviewed_at := now();
  end if;
  return new;
end $$;
drop trigger if exists subs_apply on public.subscription_payments;
create trigger subs_apply before update on public.subscription_payments
  for each row execute function public.apply_subscription();

-- Sellers submit payments as 'pending' only.
create or replace function public.force_pending() returns trigger
language plpgsql as $$
begin
  if not public.is_admin() then new.status := 'pending'; new.reviewed_at := null; end if;
  return new;
end $$;
drop trigger if exists subs_pending on public.subscription_payments;
create trigger subs_pending before insert on public.subscription_payments
  for each row execute function public.force_pending();
drop trigger if exists ideas_pending on public.ideas;
create or replace function public.force_new_idea() returns trigger
language plpgsql as $$
begin
  if not public.is_admin() then new.status := 'new'; end if;
  return new;
end $$;
create trigger ideas_pending before insert on public.ideas
  for each row execute function public.force_new_idea();

-- ============================================================
-- Row Level Security
-- ============================================================
alter table public.profiles enable row level security;
alter table public.products enable row level security;
alter table public.orders enable row level security;
alter table public.payouts enable row level security;
alter table public.subscription_payments enable row level security;
alter table public.ideas enable row level security;

-- profiles
drop policy if exists "own profile read" on public.profiles;
create policy "own profile read" on public.profiles for select using (id = auth.uid() or public.is_admin());
drop policy if exists "own profile update" on public.profiles;
create policy "own profile update" on public.profiles for update using (id = auth.uid() or public.is_admin());

-- products
drop policy if exists "products read" on public.products;
create policy "products read" on public.products for select to authenticated using (active or public.is_admin());
drop policy if exists "products admin write" on public.products;
create policy "products admin write" on public.products for all using (public.is_admin()) with check (public.is_admin());

-- orders
drop policy if exists "orders read" on public.orders;
create policy "orders read" on public.orders for select using (seller_id = auth.uid() or public.is_admin());
drop policy if exists "orders create" on public.orders;
create policy "orders create" on public.orders for insert
  with check ((seller_id = auth.uid() and public.can_sell(auth.uid())) or public.is_admin());
drop policy if exists "orders update" on public.orders;
create policy "orders update" on public.orders for update using (seller_id = auth.uid() or public.is_admin());

-- payouts
drop policy if exists "payouts read" on public.payouts;
create policy "payouts read" on public.payouts for select using (seller_id = auth.uid() or public.is_admin());
drop policy if exists "payouts admin write" on public.payouts;
create policy "payouts admin write" on public.payouts for all using (public.is_admin()) with check (public.is_admin());

-- subscription payments
drop policy if exists "subs read" on public.subscription_payments;
create policy "subs read" on public.subscription_payments for select using (seller_id = auth.uid() or public.is_admin());
drop policy if exists "subs create" on public.subscription_payments;
create policy "subs create" on public.subscription_payments for insert with check (seller_id = auth.uid() or public.is_admin());
drop policy if exists "subs admin update" on public.subscription_payments;
create policy "subs admin update" on public.subscription_payments for update using (public.is_admin());

-- ideas
drop policy if exists "ideas read" on public.ideas;
create policy "ideas read" on public.ideas for select using (user_id = auth.uid() or public.is_admin());
drop policy if exists "ideas create" on public.ideas;
create policy "ideas create" on public.ideas for insert with check (user_id = auth.uid());
drop policy if exists "ideas admin update" on public.ideas;
create policy "ideas admin update" on public.ideas for update using (public.is_admin());

-- ============================================================
-- Storage bucket for product photos (public read, admin upload)
-- ============================================================
insert into storage.buckets (id, name, public) values ('product-images', 'product-images', true)
  on conflict (id) do nothing;
drop policy if exists "product images admin upload" on storage.objects;
create policy "product images admin upload" on storage.objects for insert
  with check (bucket_id = 'product-images' and public.is_admin());
drop policy if exists "product images admin update" on storage.objects;
create policy "product images admin update" on storage.objects for update
  using (bucket_id = 'product-images' and public.is_admin());
-- Example products to start the catalog (prices in EGP). Edit or remove them from the admin panel.
insert into public.products
  (name_en, name_ar, description_en, description_ar, category, factory_code, region, quality_score,
   wholesale_price, min_price, suggested_price, ship_days, image_url, stock)
values
 ('Classic cotton shirt', 'قميص قطن كلاسيك', 'Egyptian cotton, regular fit, sizes S–XXL.', 'قطن مصري، قصّة عادية، مقاسات من S إلى XXL.', 'Clothing', 'FT-104', 'Delta', 4.8, 320, 420, 520, 2, 'products/p1.jpg', 120),
 ('Striped satin pajama set', 'بيجامة ساتان مقلمة', 'Two-piece satin set, sizes S–XL.', 'طقم ساتان قطعتين، مقاسات من S إلى XL.', 'Clothing', 'FT-104', 'Delta', 4.8, 260, 350, 430, 2, 'products/p2.jpg', 80),
 ('Kids fleece hoodie', 'هودي أطفال فليس', 'Warm fleece hoodie for ages 3–12.', 'هودي فليس دافي للأعمار من ٣ إلى ١٢ سنة.', 'Clothing', 'FT-117', 'Greater Cairo', 4.6, 210, 290, 360, 3, 'products/p3.jpg', 150),
 ('Handmade stoneware mug', 'مج فخار يدوي', 'Hand-glazed stoneware mug, 350 ml.', 'مج فخار مطلي يدويًا، ٣٥٠ مل.', 'Home', 'FH-203', 'Greater Cairo', 4.9, 120, 170, 220, 2, 'products/p4.jpg', 200),
 ('Oak serving board', 'لوح تقديم خشب', 'Solid wood serving board, 40 × 25 cm.', 'لوح تقديم من الخشب الطبيعي، ٤٠ × ٢٥ سم.', 'Home', 'FH-211', 'Greater Cairo', 4.7, 150, 220, 290, 3, 'products/p5.jpg', 60),
 ('Woven palm baskets', 'سلال خوص منسوجة', 'Set of 3 handwoven palm-leaf baskets.', 'طقم ٣ سلال خوص منسوجة يدويًا.', 'Home', 'FH-208', 'Greater Cairo', 4.5, 140, 200, 260, 2, 'products/p6.jpg', 90),
 ('Leather bifold wallet', 'محفظة جلد', 'Genuine leather wallet with 6 card slots.', 'محفظة جلد طبيعي بـ٦ أماكن للكروت.', 'Accessories', 'FA-305', 'Greater Cairo', 4.8, 160, 230, 300, 1, 'products/p7.jpg', 140),
 ('Handmade soap trio', 'طقم ٣ صابون يدوي', 'Three natural handmade soaps, 100 g each.', 'ثلاث صابونات طبيعية يدوية، ١٠٠ جم لكل واحدة.', 'Beauty', 'FB-402', 'Alexandria', 4.7, 75, 120, 160, 3, 'products/p8.jpg', 300),
 ('Pure argan hair oil', 'زيت أرجان للشعر', 'Cold-pressed argan oil, 50 ml.', 'زيت أرجان معصور على البارد، ٥٠ مل.', 'Beauty', 'FB-402', 'Alexandria', 4.7, 110, 170, 220, 3, 'products/p9.jpg', 180);
