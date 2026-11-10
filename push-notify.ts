// CepOS · push-notify (Supabase Edge Function)
// Görevleri:
//  1) { action: 'key' }  → uygulamaya açık VAPID anahtarını verir (giriş yapmış kullanıcı).
//  2) { action: 'test' } → çağıran kişinin kayıtlı cihazlarına deneme bildirimi gönderir.
//  3) Veri tabanı webhook'u (notifications tablosuna INSERT) → bildirimi ilgili cihazlara gönderir.
//     Başlıkta x-webhook-secret = PUSH_WEBHOOK_SECRET olmalı.
// Kimin aldığı:
//  - recipient doluysa yalnız o kişi; boşsa tüm aktif kullanıcılar.
//  - 'satis' ve 'iade' türleri yalnız "tüm satışları görebilir" (view_all_sales) yetkisi olanlara (sahip her zaman).
//  - İşlemi yapan kişi (actor_id) kendi işlemi için bildirim almaz.
//  - Cihazda türler seçildiyse (kinds) yalnız o türler gider.
//  - Öncelik: acil → yüksek öncelik + ekranda kalır; bilgi → sessiz; normal → normal.
// Gizli anahtarlar (Edge Functions > Secrets): VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY, VAPID_SUBJECT, PUSH_WEBHOOK_SECRET.
// SUPABASE_URL, SUPABASE_ANON_KEY ve SUPABASE_SERVICE_ROLE_KEY Supabase tarafından otomatik verilir.
// Dağıtım: "Verify JWT" KAPALI olmalı (webhook JWT göndermez); kullanıcı istekleri burada ayrıca doğrulanır.

import webpush from 'npm:web-push@3.6.7';
import { createClient } from 'npm:@supabase/supabase-js@2.45.4';

const URL_ = Deno.env.get('SUPABASE_URL')!;
const ANON = Deno.env.get('SUPABASE_ANON_KEY')!;
const SERVICE = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const PUB = Deno.env.get('VAPID_PUBLIC_KEY') ?? '';
const PRIV = Deno.env.get('VAPID_PRIVATE_KEY') ?? '';
const SUBJECT = Deno.env.get('VAPID_SUBJECT') ?? '';
const HOOK = Deno.env.get('PUSH_WEBHOOK_SECRET') ?? '';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};
const json = (b: unknown, status = 200) =>
  new Response(JSON.stringify(b), { status, headers: { ...CORS, 'Content-Type': 'application/json' } });

const admin = createClient(URL_, SERVICE, { auth: { persistSession: false } });

// bildirime dokununca açılacak ekran (uygulamadaki NREF ile aynı)
const REF_TAB: Record<string, string> = {
  sales: 'satislar', sale_returns: 'iadeler', service_orders: 'servis', customer_orders: 'siparis', follow_ups: 'siparis',
  tasks: 'gorev', quotes: 'teklif', shortages: 'eksikler', accessories: 'aksesuar', shifts: 'vardiya', targets: 'hedef',
  day_closings: 'kasa', expenses: 'odemeler', term_debts: 'odemeler', entitlements: 'hakedis', commissions: 'primler',
  products: 'stok', device_inspections: 'stok', role_permissions: 'yonetim', profiles: 'yonetim', trainings: 'egitim',
};
const KIND_TAB: Record<string, string> = {
  satis: 'satislar', iade: 'iadeler', servis: 'servis', siparis: 'siparis', gorev: 'gorev', vardiya: 'vardiya',
  kasa: 'kasa', odeme: 'odemeler', stok: 'aksesuar', hedef: 'hedef', hakedis: 'hakedis', teklif: 'teklif', ozet: 'panel', denetim: 'yonetim',
};

type Sub = { id: string; user_id: string; endpoint: string; p256dh: string; auth: string; kinds: string[] | null };
type Payload = { title: string; body: string; url: string; tag?: string; priority: string };

function ready() {
  if (!PUB || !PRIV || !SUBJECT) return 'Bildirim anahtarları eksik (VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY, VAPID_SUBJECT).';
  webpush.setVapidDetails(SUBJECT, PUB, PRIV);
  return '';
}

async function sendTo(subs: Sub[], p: Payload) {
  let sent = 0;
  const gone: string[] = [];
  const okIds: string[] = [];
  await Promise.all(subs.map(async (s) => {
    try {
      await webpush.sendNotification(
        { endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } },
        JSON.stringify(p),
        { TTL: 86400, urgency: p.priority === 'acil' ? 'high' : p.priority === 'bilgi' ? 'low' : 'normal' },
      );
      sent++;
      okIds.push(s.id);
    } catch (e) {
      const code = (e as { statusCode?: number }).statusCode;
      if (code === 404 || code === 410) gone.push(s.id);   // cihaz aboneliği artık geçersiz
      else console.error('push hata', code, (e as Error).message);
    }
  }));
  if (gone.length) await admin.from('push_subscriptions').delete().in('id', gone);
  if (okIds.length) await admin.from('push_subscriptions').update({ last_ok_at: new Date().toISOString() }).in('id', okIds);
  return sent;
}

// kişinin yetkisi (sahip her şeye yetkili)
async function allowedUsers(userIds: string[], perm: string) {
  const { data: profs } = await admin.from('profiles').select('id, role, active').in('id', userIds);
  const { data: rp } = await admin.from('role_permissions').select('role, allowed').eq('permission', perm);
  const okRoles = new Set((rp ?? []).filter((r) => r.allowed).map((r) => String(r.role)));
  return new Set((profs ?? []).filter((p) => p.active && (p.role === 'owner' || okRoles.has(String(p.role)))).map((p) => p.id));
}

async function handleWebhook(body: any) {
  const n = body?.record;
  if (!n || body?.table !== 'notifications' || body?.type !== 'INSERT') return json({ skipped: 'not a notification insert' });
  const err = ready();
  if (err) return json({ error: err }, 500);

  let q = admin.from('push_subscriptions').select('id, user_id, endpoint, p256dh, auth, kinds');
  if (n.recipient) q = q.eq('user_id', n.recipient);
  const { data: subs0, error } = await q;
  if (error) return json({ error: error.message }, 500);
  let subs = (subs0 ?? []) as Sub[];
  subs = subs.filter((s) => s.user_id !== n.actor_id && (!s.kinds || s.kinds.length === 0 || s.kinds.includes(n.kind)));
  if (!subs.length) return json({ sent: 0 });

  // aktif kullanıcılar; satış/iade tutarları yalnız yetkililere
  const ids = [...new Set(subs.map((s) => s.user_id))];
  const { data: act } = await admin.from('profiles').select('id').in('id', ids).eq('active', true);
  const active = new Set((act ?? []).map((p) => p.id));
  subs = subs.filter((s) => active.has(s.user_id));
  if (!n.recipient && (n.kind === 'satis' || n.kind === 'iade')) {
    const ok = await allowedUsers(ids, 'view_all_sales');
    subs = subs.filter((s) => ok.has(s.user_id));
  }
  if (!subs.length) return json({ sent: 0 });

  const tab = REF_TAB[n.ref_table] ?? KIND_TAB[n.kind] ?? 'panel';
  const sent = await sendTo(subs, {
    title: String(n.title ?? 'CepOS').slice(0, 120),
    body: String(n.body ?? '').slice(0, 300),
    url: '#' + tab,
    tag: n.id,
    priority: n.priority ?? 'normal',
  });
  return json({ sent });
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS });
  if (req.method !== 'POST') return json({ error: 'Yalnız POST' }, 405);
  let body: any = {};
  try { body = await req.json(); } catch { body = {}; }

  // 3) veri tabanı webhook'u
  const hook = req.headers.get('x-webhook-secret');
  if (hook !== null) {
    if (!HOOK || hook !== HOOK) return json({ error: 'Geçersiz webhook anahtarı' }, 401);
    return await handleWebhook(body);
  }

  // 1-2) uygulamadan gelen istek: oturum doğrulanır
  const token = (req.headers.get('Authorization') ?? '').replace(/^Bearer\s+/i, '');
  const userClient = createClient(URL_, ANON, { global: { headers: { Authorization: `Bearer ${token}` } }, auth: { persistSession: false } });
  const { data: u, error: ue } = await userClient.auth.getUser(token);
  if (ue || !u?.user) return json({ error: 'Oturum geçersiz, yeniden giriş yapın.' }, 401);
  const { data: prof } = await admin.from('profiles').select('id, active').eq('id', u.user.id).maybeSingle();
  if (!prof?.active) return json({ error: 'Kullanıcı aktif değil.' }, 403);

  if (body?.action === 'key') {
    if (!PUB) return json({ error: 'Bildirim sunucusu kurulu ama VAPID_PUBLIC_KEY gizli anahtarı eklenmemiş.' }, 500);
    return json({ publicKey: PUB });
  }
  if (body?.action === 'test') {
    const err = ready();
    if (err) return json({ error: err }, 500);
    const { data: subs } = await admin.from('push_subscriptions').select('id, user_id, endpoint, p256dh, auth, kinds').eq('user_id', u.user.id);
    if (!subs?.length) return json({ error: 'Bu hesapta kayıtlı cihaz yok. Önce “Bu cihazda aç” deyin.' }, 400);
    const sent = await sendTo(subs as Sub[], { title: 'CepOS · deneme', body: 'Telefon bildirimleri çalışıyor ✓', url: '#panel', tag: 'test', priority: 'normal' });
    return json({ sent });
  }
  return json({ error: 'Bilinmeyen işlem' }, 400);
});
