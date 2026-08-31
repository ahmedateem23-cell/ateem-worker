const ODOO_URL = "https://www.ateem-store.com";
const ODOO_DB = "ateem-store";
const ODOO_LOGIN = "ateemstore430@gmail.com";

/* ═══ إشعارات Push للعميل عبر Firebase Cloud Messaging (FCM) ═══
   ملاحظة الفوترة: FCM مجاني بالكامل، مفيش حد أقصى مدفوع. الاعتماد
   بيتم عبر Service Account (FIREBASE_SERVICE_ACCOUNT_KEY سيكرت)
   بدل مفتاح ثابت، عشان كده لازم نعمل توقيع JWT ونستبدله بـ access
   token من جوجل قبل كل إرسال. */

function base64UrlEncode(bytes) {
  let binary = "";
  const arr = bytes instanceof Uint8Array ? bytes : new TextEncoder().encode(bytes);
  for (let i = 0; i < arr.length; i++) binary += String.fromCharCode(arr[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function pemToArrayBuffer(pem) {
  const b64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s/g, "");
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function getFirebaseAccessToken(env) {
  const svc = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT_KEY);
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const claims = {
    iss: svc.client_email,
    scope: "https://www.googleapis.com/auth/firebase.messaging",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
  };
  const unsigned = base64UrlEncode(JSON.stringify(header)) + "." + base64UrlEncode(JSON.stringify(claims));

  const key = await crypto.subtle.importKey(
    "pkcs8",
    pemToArrayBuffer(svc.private_key),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(unsigned)
  );
  const jwt = unsigned + "." + base64UrlEncode(new Uint8Array(signature));

  const tokenResp = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=" + jwt,
  });
  const tokenData = await tokenResp.json();
  if (!tokenData.access_token) throw new Error("Firebase auth failed: " + JSON.stringify(tokenData));
  return { accessToken: tokenData.access_token, projectId: svc.project_id };
}

async function sendCustomerPushNotification(env, deviceToken, title, body, data = {}) {
  const { accessToken, projectId } = await getFirebaseAccessToken(env);
  const resp = await fetch(
    `https://fcm.googleapis.com/v1/projects/${projectId}/messages:send`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${accessToken}`,
      },
      body: JSON.stringify({
        message: {
          token: deviceToken,
          notification: { title, body },
          data,
        },
      }),
    }
  );
  if (!resp.ok) {
    const errText = await resp.text();
    throw new Error(`FCM send failed: ${resp.status} ${errText}`);
  }
}

/* ═══ Helpers مشتركة لتتبّع الأجهزة/السلة والحد من الإشعارات ═══
   المفاتيح المستخدمة في ATEEM_KV:
   - device:phone:<phone>   → { fcmToken, updatedAt }  (دائم، بدون TTL)
   - cart:<phone>           → { items, updatedAt, notifiedAt } (TTL 7 أيام)
   - lastorder:<phone>      → "<ISO timestamp>" لآخر طلب اتعمل (TTL 60 يوم)
   - lastnotify:<phone>     → "<ISO timestamp>" لآخر إشعار استباقي اتبعت
     (سلة متروكة أو تنبيه ذوق) — بيُستخدم لفرض حد "إشعار واحد كل 48 ساعة"
     بغض النظر عن نوع الإشعار. */

function normalizePhone(phone) {
  return String(phone || "").replace(/[^\d+]/g, "");
}

const NOTIFY_COOLDOWN_MS = 48 * 60 * 60 * 1000;

async function canNotifyCustomer(env, phone) {
  if (!env.ATEEM_KV) return false;
  const last = await env.ATEEM_KV.get(`lastnotify:${phone}`);
  if (!last) return true;
  return Date.now() - Date.parse(last) >= NOTIFY_COOLDOWN_MS;
}

async function markCustomerNotified(env, phone) {
  if (!env.ATEEM_KV) return;
  await env.ATEEM_KV.put(`lastnotify:${phone}`, new Date().toISOString(), {
    expirationTtl: 60 * 60 * 24 * 30,
  });
}

async function getDeviceToken(env, phone) {
  if (!env.ATEEM_KV) return null;
  const raw = await env.ATEEM_KV.get(`device:phone:${phone}`);
  if (!raw) return null;
  try { return JSON.parse(raw).fcmToken || null; } catch (e) { return null; }
}

/* ═══ منطق تأكيد الطلب المشترك — idempotent ═══
   بيتنادى من مسارين: الرابط القديم /odoo-confirm-order (كصفحة ويب)
   وزرار تليجرام الجديد (callback_data) عبر /telegram-webhook.
   لو الطلب already بحالة "sale" أو "done" (يعني اتأكد قبل كده)،
   الدالة بترجع alreadyConfirmed:true من غير ما تعيد بعت الإيميل ولا
   رسالة تليجرام تانية ولا الـ push — كده مينفعش حد يدوس على نفس
   الزرار مرتين (أو يفتح نفس الرابط مرتين) ويطلع إشعارات مكررة. */
async function confirmOdooOrder(env, orderId) {
  if (!orderId) {
    return { ok: false, status: 400, message: "رقم الطلب ناقص" };
  }

  const loginResp = await fetch(`${ODOO_URL}/jsonrpc`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      method: "call",
      params: {
        service: "common",
        method: "login",
        args: [ODOO_DB, ODOO_LOGIN, env.ODOO_API_KEY],
      },
    }),
  });
  const loginData = await loginResp.json();
  const uid = loginData.result;
  if (!uid) {
    return { ok: false, status: 401, message: "فشل تسجيل الدخول لـ Odoo" };
  }

  const callKw = async (model, method, args, kwargs = {}) => {
    const resp = await fetch(`${ODOO_URL}/jsonrpc`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        method: "call",
        params: {
          service: "object",
          method: "execute_kw",
          args: [ODOO_DB, uid, env.ODOO_API_KEY, model, method, args, kwargs],
        },
      }),
    });
    const data = await resp.json();
    if (data.error) throw new Error(JSON.stringify(data.error));
    return data.result;
  };

  const before = await callKw("sale.order", "read", [[orderId], ["name", "state", "amount_total"]]);
  if (!before || !before.length) {
    return { ok: false, status: 404, message: "الطلب مش موجود" };
  }
  const orderName = before[0].name;

  // نقطة الـ idempotency: لو الطلب already مؤكد، منوقفش هنا بس —
  // منبعتش تاني أي إشعار (إيميل/تليجرام/push) تحت في الدالة دي كمان.
  const alreadyConfirmed = before[0].state === "sale" || before[0].state === "done";

  if (!alreadyConfirmed) {
    await callKw("sale.order", "action_confirm", [[orderId]]);
  }

  let emailSent = false;
  if (!alreadyConfirmed) {
    try {
      const templateRef = await callKw("ir.model.data", "search_read", [
        [["module", "=", "sale"], ["name", "=", "email_template_edi_sale"]],
        ["res_id"],
      ], { limit: 1 });
      if (templateRef && templateRef.length) {
        await callKw("mail.template", "send_mail", [templateRef[0].res_id, orderId], { force_send: true });
        emailSent = true;
      }
    } catch (emailErr) {
      emailSent = false;
    }

    try {
      if (env.TELEGRAM_BOT_TOKEN && env.TELEGRAM_CHAT_ID) {
        await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            chat_id: env.TELEGRAM_CHAT_ID,
            text: `✅ تم تأكيد الدفع والطلب\n\n🧾 رقم الطلب: ${orderName}\n💰 الإجمالي: ${before[0].amount_total != null ? before[0].amount_total.toLocaleString('en-US') + ' SDG' : 'غير متاح'}`,
          }),
        });
      }
    } catch (tgErr) {
      // best-effort
    }

    try {
      if (env.ATEEM_KV && env.FIREBASE_SERVICE_ACCOUNT_KEY) {
        const deviceToken = await env.ATEEM_KV.get(`device:${orderId}`);
        if (deviceToken) {
          await sendCustomerPushNotification(
            env,
            deviceToken,
            "تم تأكيد طلبك ✅",
            `رقم الطلب: ${orderName} — جاري تجهيزه الآن.`,
            { orderId: String(orderId), orderName, type: "order_confirmed" }
          );
          await env.ATEEM_KV.delete(`device:${orderId}`);
        }
      }
    } catch (pushErr) {
      // best-effort — فشل الإشعار مايأثرش على نجاح تأكيد الطلب
    }
  }

  return { ok: true, orderId, orderName, alreadyConfirmed, emailSent };
}

/* رد سريع على ضغطة الزرار — بيقفل حالة "التحميل" اللي بتظهر لتليجرام
   على الزرار نفسه، ولو showAlert=true بيطلع كـ popup بدل toast صغير. */
async function answerTelegramCallback(env, callbackQueryId, text, showAlert = false) {
  try {
    await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/answerCallbackQuery`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        callback_query_id: callbackQueryId,
        text: text ? String(text).slice(0, 200) : undefined,
        show_alert: showAlert,
      }),
    });
  } catch (e) {
    // best-effort
  }
}

/* ═══ Cron: سلة متروكة + تنبيه ذوق كل أسبوعين ═══
   لازم تسجيل الجدولة في wrangler.toml، مثلاً كل ساعة:
     [triggers]
     crons = ["0 * * * *"]
   كل دورة بتفحص العملاء اللي عندهم سلة/طلب سابق مسجّل في ATEEM_KV،
   وبتبعت إشعار واحد بالحد الأقصى لكل عميل كل 48 ساعة (عبر
   canNotifyCustomer/markCustomerNotified) — بغض النظر إن كان الإشعار
   سلة متروكة أو تنبيه ذوق، فمينفعش عميل ياخد الاتنين في نفس اليوم. */

const ABANDONED_CART_MIN_AGE_MS = 3 * 60 * 60 * 1000; // 3 ساعات من آخر تحديث للسلة
const TASTE_ALERT_MIN_GAP_MS = 14 * 24 * 60 * 60 * 1000; // أسبوعين من آخر طلب

async function runAbandonedCartCheck(env) {
  if (!env.ATEEM_KV || !env.FIREBASE_SERVICE_ACCOUNT_KEY) return;
  let cursor;
  do {
    const list = await env.ATEEM_KV.list({ prefix: "cart:", cursor });
    for (const key of list.keys) {
      const phone = key.name.slice("cart:".length);
      try {
        const raw = await env.ATEEM_KV.get(key.name);
        if (!raw) continue;
        const cart = JSON.parse(raw);
        if (cart.notifiedAt) continue; // اتبعت له تذكير بالفعل لنفس السلة

        const ageMs = Date.now() - Date.parse(cart.updatedAt);
        if (ageMs < ABANDONED_CART_MIN_AGE_MS) continue;

        if (!(await canNotifyCustomer(env, phone))) continue;

        const deviceToken = await getDeviceToken(env, phone);
        if (!deviceToken) continue;

        const firstItemName = (cart.items && cart.items[0] && cart.items[0].name) || "المنتج اللي شفته";
        await sendCustomerPushNotification(
          env, deviceToken,
          "سلتك في انتظارك 💎",
          `${firstItemName} لسه محفوظ ليك — أكمل طلبك قبل ما ينفد.`,
          { type: "abandoned_cart" }
        );

        cart.notifiedAt = new Date().toISOString();
        await env.ATEEM_KV.put(key.name, JSON.stringify(cart), { expirationTtl: 60 * 60 * 24 * 7 });
        await markCustomerNotified(env, phone);
      } catch (e) {
        // best-effort — فشل عميل واحد ميوقفش الباقي
      }
    }
    cursor = list.list_complete ? undefined : list.cursor;
  } while (cursor);
}

async function runTasteAlertCheck(env) {
  if (!env.ATEEM_KV || !env.FIREBASE_SERVICE_ACCOUNT_KEY) return;
  let cursor;
  do {
    const list = await env.ATEEM_KV.list({ prefix: "lastorder:", cursor });
    for (const key of list.keys) {
      const phone = key.name.slice("lastorder:".length);
      try {
        const lastOrderIso = await env.ATEEM_KV.get(key.name);
        if (!lastOrderIso) continue;

        const gapMs = Date.now() - Date.parse(lastOrderIso);
        if (gapMs < TASTE_ALERT_MIN_GAP_MS) continue;

        if (!(await canNotifyCustomer(env, phone))) continue;

        const deviceToken = await getDeviceToken(env, phone);
        if (!deviceToken) continue;

        await sendCustomerPushNotification(
          env, deviceToken,
          "وصل جديد يليق بذوقك 💎",
          "قطع جديدة في ATEEM اخترناها بعناية — ألق نظرة قبل ما تخلص.",
          { type: "taste_alert" }
        );
        await markCustomerNotified(env, phone);
      } catch (e) {
        // best-effort
      }
    }
    cursor = list.list_complete ? undefined : list.cursor;
  } while (cursor);
}

export default {
  async fetch(request, env) {
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);

    // مسار جلب منتجات المتجر من Odoo
    if (url.pathname === "/odoo-products") {
      try {
        // خطوة 1: تسجيل دخول (uid) باستخدام مفتاح الـ API
        const loginResp = await fetch(`${ODOO_URL}/jsonrpc`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            jsonrpc: "2.0",
            method: "call",
            params: {
              service: "common",
              method: "login",
              args: [ODOO_DB, ODOO_LOGIN, env.ODOO_API_KEY],
            },
          }),
        });
        const loginData = await loginResp.json();
        const uid = loginData.result;
        if (!uid) {
          return new Response(JSON.stringify({ ok: false, error: "Odoo login failed", detail: loginData }), {
            status: 401,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          });
        }

        // خطوة 2: قراءة المنتجات المنشورة على الموقع فقط
        const readResp = await fetch(`${ODOO_URL}/jsonrpc`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            jsonrpc: "2.0",
            method: "call",
            params: {
              service: "object",
              method: "execute_kw",
              args: [
                ODOO_DB,
                uid,
                env.ODOO_API_KEY,
                "product.template",
                "search_read",
                [[["website_published", "=", true]]],
                {
                  fields: ["id", "name", "list_price", "description_sale", "categ_id", "create_date", "sales_count", "write_date"],
                  limit: 200,
                },
              ],
            },
          }),
        });
        const readData = await readResp.json();
        if (readData.error) {
          return new Response(JSON.stringify({ ok: false, error: "Odoo read failed", detail: readData.error }), {
            status: 500,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          });
        }

        // البادج مش ثابت ولا عشوائي: "جديد" لو المنتج اتنشر آخر 30 يوم،
        // و"الأكثر مبيعاً" لأعلى 10 منتجات فعليًا حسب sales_count من Odoo.
        // منتج بلا أي منهم ببساطة بيرجع badge: null.
        const NEW_WINDOW_DAYS = 30;
        const now = Date.now();
        const bestSellerIds = new Set(
          (readData.result || [])
            .filter((p) => (p.sales_count || 0) > 0)
            .sort((a, b) => (b.sales_count || 0) - (a.sales_count || 0))
            .slice(0, 10)
            .map((p) => p.id)
        );

        const products = (readData.result || []).map((p) => {
          let badge = null;
          const createdMs = p.create_date ? Date.parse(p.create_date.replace(" ", "T") + "Z") : null;
          const isNew = createdMs && (now - createdMs) / 86400000 <= NEW_WINDOW_DAYS;
          if (isNew) badge = "جديد";
          else if (bestSellerIds.has(p.id)) badge = "الأكثر مبيعاً";

          return {
            id: p.id,
            name: p.name,
            price: p.list_price,
            currency: "SDG",
            description: p.description_sale || "",
            category: p.categ_id ? p.categ_id[1] : "",
            image: `${ODOO_URL}/web/image/product.template/${p.id}/image_1024`,
            // آخر تعديل حقيقي على المنتج في Odoo — التطبيق يقارنه باللي
            // عنده محفوظ محليًا، ولو مختلف يعرف إنه لازم يحدّث الصورة/
            // البيانات بدل ما يفضل عايش على نسخة قديمة من الكاش.
            updatedAt: p.write_date || null,
            badge,
            isNew,
            isBestSeller: bestSellerIds.has(p.id),
          };
        });

        return new Response(JSON.stringify({ ok: true, products }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      } catch (e) {
        return new Response(JSON.stringify({ ok: false, error: String(e) }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
    }

    // تسجيل توكن الجهاز بشكل دائم مربوط برقم هاتف العميل — مستقل عن أي
    // طلب معيّن، عشان نقدر نبعت إشعارات استباقية (سلة متروكة/تنبيه ذوق)
    // حتى لو العميل معندوش طلب مفتوح دلوقتي. لو العميل بدّل جهازه أو
    // أعاد تثبيت التطبيق، آخر توكن مسجّل هو اللي بيتحفظ (استبدال كامل).
    if (url.pathname === "/register-device") {
      if (request.method !== "POST") {
        return new Response("Method not allowed", { status: 405, headers: corsHeaders });
      }
      try {
        const body = await request.json();
        const phone = normalizePhone(body.phone);
        const fcmToken = body.fcmToken;
        if (!phone || !fcmToken) {
          return new Response(JSON.stringify({ ok: false, error: "missing phone or fcmToken" }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          });
        }
        if (!env.ATEEM_KV) {
          return new Response(JSON.stringify({ ok: false, error: "KV not configured" }), {
            status: 500,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          });
        }
        await env.ATEEM_KV.put(
          `device:phone:${phone}`,
          JSON.stringify({ fcmToken, updatedAt: new Date().toISOString() })
        );
        return new Response(JSON.stringify({ ok: true }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      } catch (e) {
        return new Response(JSON.stringify({ ok: false, error: String(e) }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
    }

    // نقطة تحويل نص لصوت (Text-to-Speech) — بيستخدمها التطبيق لقراءة
    // ردود البوت بصوت عالٍ. مفتاح ElevenLabs وvoice ID سيكرتات
    // سيرفر-سايد بس (ELEVENLABS_API_KEY / ELEVENLABS_VOICE_ID)، التطبيق
    // مايشوفهمش خالص ولا بيبعت غير النص. بيرجّع صوت MP3 خام مباشرة.
    if (url.pathname === "/tts") {
      if (request.method !== "POST") {
        return new Response("Method not allowed", { status: 405, headers: corsHeaders });
      }
      try {
        const body = await request.json();
        // حد أقصى معقول للنص عشان نتحكم في تكلفة كل طلب صوت
        const text = String(body.text || "").trim().slice(0, 600);
        if (!text) {
          return new Response(JSON.stringify({ ok: false, error: "missing text" }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          });
        }
        if (!env.ELEVENLABS_API_KEY || !env.ELEVENLABS_VOICE_ID) {
          return new Response(JSON.stringify({ ok: false, error: "TTS not configured" }), {
            status: 500,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          });
        }

        const elResp = await fetch(
          `https://api.elevenlabs.io/v1/text-to-speech/${env.ELEVENLABS_VOICE_ID}`,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "xi-api-key": env.ELEVENLABS_API_KEY,
              "Accept": "audio/mpeg",
            },
            body: JSON.stringify({
              text,
              model_id: "eleven_multilingual_v2", // الموديل الوحيد اللي بيدعم العربي فعليًا
              voice_settings: { stability: 0.5, similarity_boost: 0.75 },
            }),
          }
        );

        if (!elResp.ok) {
          const errText = await elResp.text();
          throw new Error(`ElevenLabs TTS failed: ${elResp.status} ${errText}`);
        }

        const audioBuffer = await elResp.arrayBuffer();
        return new Response(audioBuffer, {
          headers: { ...corsHeaders, "Content-Type": "audio/mpeg" },
        });
      } catch (e) {
        return new Response(JSON.stringify({ ok: false, error: String(e) }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
    }

    // تسجيل حدث سلة (إضافة/تحديث) — بيتخزن snapshot بسيط لمحتوى السلة
    // مع وقت آخر تحديث، عشان الـ scheduled() تحت تقدر تكتشف "سلة متروكة"
    // (سلة اتحدثت ومفيش طلب اتعمل بعدها بفترة كافية) وتبعت تذكير واحد.
    // كل حدث جديد بيصفّر notifiedAt عشان يبدأ دورة جديدة قابلة للتذكير.
    if (url.pathname === "/cart-event") {
      if (request.method !== "POST") {
        return new Response("Method not allowed", { status: 405, headers: corsHeaders });
      }
      try {
        const body = await request.json();
        const phone = normalizePhone(body.phone);
        const items = Array.isArray(body.items) ? body.items : [];
        if (!phone || !items.length) {
          return new Response(JSON.stringify({ ok: false, error: "missing phone or items" }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          });
        }
        if (!env.ATEEM_KV) {
          return new Response(JSON.stringify({ ok: false, error: "KV not configured" }), {
            status: 500,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          });
        }
        await env.ATEEM_KV.put(
          `cart:${phone}`,
          JSON.stringify({ items, updatedAt: new Date().toISOString(), notifiedAt: null }),
          { expirationTtl: 60 * 60 * 24 * 7 }
        );
        return new Response(JSON.stringify({ ok: true }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      } catch (e) {
        return new Response(JSON.stringify({ ok: false, error: String(e) }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
    }

    // مسار إشعارات تليجرام للطلبات
    if (url.pathname === "/telegram-order") {
      if (request.method !== "POST") {
        return new Response("Method not allowed", { status: 405, headers: corsHeaders });
      }
      try {
        const order = await request.json();
        const text =
          "🛍️ طلب جديد من تطبيق ATEEM\n\n" +
          "👤 الاسم: " + (order.name || "-") + "\n" +
          "📦 المنتج: " + (order.product || "-") + "\n" +
          (order.size ? "📏 المقاس: " + order.size + "\n" : "") +
          "📍 العنوان: " + (order.address || "-") + "\n" +
          "📞 الهاتف: " + (order.phone || "-") + "\n\n" +
          "💵 الدفع: عند الاستلام";

        const tgResp = await fetch(
          `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ chat_id: env.TELEGRAM_CHAT_ID, text }),
          }
        );
        if (!tgResp.ok) throw new Error(`Telegram HTTP ${tgResp.status}`);
        return new Response(JSON.stringify({ ok: true }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      } catch (e) {
        return new Response(JSON.stringify({ ok: false, error: String(e) }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
    }

    // نقطة تفاصيل منتج واحد — الخيارات/الفاريانتس/المخزون الحقيقية من Odoo
    if (url.pathname === "/odoo-product-detail") {
      try {
        const productId = parseInt(url.searchParams.get("id"), 10);
        if (!productId) {
          return new Response(JSON.stringify({ ok: false, error: "missing id" }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          });
        }

        // خطوة 1: تسجيل الدخول
        const loginResp = await fetch(`${ODOO_URL}/jsonrpc`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            jsonrpc: "2.0",
            method: "call",
            params: {
              service: "common",
              method: "login",
              args: [ODOO_DB, ODOO_LOGIN, env.ODOO_API_KEY],
            },
          }),
        });
        const loginData = await loginResp.json();
        const uid = loginData.result;
        if (!uid) {
          return new Response(JSON.stringify({ ok: false, error: "Odoo login failed" }), {
            status: 401,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          });
        }

        const callKw = async (model, method, args, kwargs = {}) => {
          const resp = await fetch(`${ODOO_URL}/jsonrpc`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              jsonrpc: "2.0",
              method: "call",
              params: {
                service: "object",
                method: "execute_kw",
                args: [ODOO_DB, uid, env.ODOO_API_KEY, model, method, args, kwargs],
              },
            }),
          });
          const data = await resp.json();
          if (data.error) throw new Error(JSON.stringify(data.error));
          return data.result;
        };

        // خطوة 2: قراءة المنتج (product.template) — بما فيها خطوط الخصائص
        const templates = await callKw("product.template", "read", [
          [productId],
          ["id", "name", "list_price", "description_sale", "categ_id",
           "attribute_line_ids", "product_variant_ids", "product_template_image_ids", "write_date"],
        ]);
        if (!templates || !templates.length) {
          return new Response(JSON.stringify({ ok: false, error: "product not found" }), {
            status: 404,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          });
        }
        const tmpl = templates[0];

        // خطوة 3: قراءة خطوط الخصائص وتقسيمها لنوعين حسب Odoo نفسه:
        // - خصائص "always/dynamic" → فعليًا بتكوّن SKU مختلف (مقاس/لون/حجم) → options
        // - خصائص "no_variant" → معلومة عن المنتج بس، مش بتغيّر الـ SKU (مادة/بلد/عناية) → specs
        // التقسيم ده جايّ من إعداد الخاصية في Odoo نفسه، مفيش أي تخمين هنا.
        let options = [];
        let specs = [];
        if (tmpl.attribute_line_ids && tmpl.attribute_line_ids.length) {
          const lines = await callKw("product.template.attribute.line", "read", [
            tmpl.attribute_line_ids,
            ["attribute_id", "value_ids"],
          ]);
          const attrIds = lines.map((l) => l.attribute_id[0]);
          const attrs = attrIds.length
            ? await callKw("product.attribute", "read", [attrIds, ["id", "name", "create_variant"]])
            : [];
          const attrById = {};
          attrs.forEach((a) => (attrById[a.id] = a));

          const allValueIds = [...new Set(lines.flatMap((l) => l.value_ids))];
          const values = allValueIds.length
            ? await callKw("product.attribute.value", "read", [allValueIds, ["id", "name"]])
            : [];
          const valueNameById = {};
          values.forEach((v) => (valueNameById[v.id] = v.name));

          lines.forEach((l) => {
            const attr = attrById[l.attribute_id[0]];
            if (!attr) return;
            const valueNames = l.value_ids.map((vid) => valueNameById[vid]).filter(Boolean);
            if (attr.create_variant === "no_variant") {
              if (valueNames.length) specs.push({ name: attr.name, value: valueNames.join("، ") });
            } else {
              options.push({ name: attr.name, values: valueNames });
            }
          });
        }

        // خطوة 4: قراءة الفاريانتس الفعلية (product.product) — السعر والمخزون
        // الحقيقيين لكل تركيبة، مش مجرد قائمة القيم النظرية.
        let variants = [];
        let totalStock = 0;
        if (tmpl.product_variant_ids && tmpl.product_variant_ids.length) {
          const variantRecords = await callKw("product.product", "read", [
            tmpl.product_variant_ids,
            ["id", "lst_price", "qty_available",
             "product_template_attribute_value_ids", "write_date"],
          ]);

          const allPtavIds = [
            ...new Set(variantRecords.flatMap((v) => v.product_template_attribute_value_ids)),
          ];
          const ptavRecords = allPtavIds.length
            ? await callKw("product.template.attribute.value", "read", [
                allPtavIds,
                ["id", "attribute_id", "name"],
              ])
            : [];
          const ptavById = {};
          ptavRecords.forEach((p) => (ptavById[p.id] = p));

          variants = variantRecords.map((v) => {
            const valuesMap = {};
            (v.product_template_attribute_value_ids || []).forEach((ptavId) => {
              const ptav = ptavById[ptavId];
              if (!ptav) return;
              // ptav.name from Odoo comes as "Attribute: Value" or similar depending
              // on version — safest is to match it back against our options list by
              // checking which option's values contain this value's plain name.
              const plainName = ptav.name.includes(":")
                ? ptav.name.split(":").slice(1).join(":").trim()
                : ptav.name;
              const matchingOption = options.find((o) => o.values.includes(plainName));
              if (matchingOption) valuesMap[matchingOption.name] = plainName;
            });
            totalStock += Math.max(0, v.qty_available || 0);
            return {
              id: v.id,
              values: valuesMap,
              price: v.lst_price,
              stock: Math.max(0, Math.floor(v.qty_available || 0)),
              updatedAt: v.write_date || null,
              // صورة الـ variant نفسه (product.product) — لو أحمد رفع صورة
              // مخصوصة لهذا اللون/المقاس من "الصورة الرئيسية" بتاعة الـ
              // variant في Odoo، هترجع هنا تلقائيًا. لو معملش كده، Odoo
              // نفسه بيرجّع صورة القالب العامة (fallback تلقائي من عنده،
              // مش لازم أي منطق إضافي هنا).
              image: `${ODOO_URL}/web/image/product.product/${v.id}/image_1024`,
            };
          });
        }

        // خطوة 5: صور المعرض (product.image) — الصور الإضافية اللي بتتحط
        // في Odoo على منتج معين. لو الصورة متربطة بـ variant بعينه
        // (product_variant_id) نحدد لونه من قائمة الفاريانتس اللي جهزناها
        // فوق، ونجمعها تحت اسم اللون ده. لو مش متربطة بـ variant (يعني
        // صورة عامة على القالب) بتتحط كـ "صور عامة" وتتعرض لأي لون معندوش
        // صور خاصة بيه لسه.
        // اسم خاصية اللون في Odoo مش دايمًا "اللون" بالعربي — ممكن يكون
        // "color"/"colour" بالإنجليزي حسب إعداد المتجر، فبنقارن بغض النظر
        // عن اللغة/الحالة بدل ما نتوقف على نص واحد بالظبط.
        const COLOR_ATTR_NAMES = ["اللون", "لون", "color", "colour"];
        const isColorAttrName = (name) =>
          !!name && COLOR_ATTR_NAMES.includes(String(name).trim().toLowerCase());
        let colorImages = {};
        let genericImages = [];
        if (tmpl.product_template_image_ids && tmpl.product_template_image_ids.length) {
          const imageRecords = await callKw("product.image", "read", [
            tmpl.product_template_image_ids,
            ["id", "product_variant_id", "write_date"],
          ]);
          const variantColorById = {};
          variants.forEach((v) => {
            const colorKey = v.values && Object.keys(v.values).find(isColorAttrName);
            if (colorKey) variantColorById[v.id] = v.values[colorKey];
          });
          imageRecords.forEach((img) => {
            const entry = {
              url: `${ODOO_URL}/web/image/product.image/${img.id}/image_1024`,
              updatedAt: img.write_date || null,
            };
            const variantId = img.product_variant_id ? img.product_variant_id[0] : null;
            const colorName = variantId ? variantColorById[variantId] : null;
            if (colorName) {
              if (!colorImages[colorName]) colorImages[colorName] = [];
              colorImages[colorName].push(entry);
            } else {
              genericImages.push(entry);
            }
          });
        }

        const product = {
          id: tmpl.id,
          name: tmpl.name,
          price: tmpl.list_price,
          description: tmpl.description_sale || "",
          category: tmpl.categ_id ? tmpl.categ_id[1] : "",
          image: `${ODOO_URL}/web/image/product.template/${tmpl.id}/image_1024`,
          // صور إضافية عامة (مش خاصة بلون معين) — تتعرض كـ fallback لأي
          // لون معندوش صور خاصة بيه.
          images: genericImages,
          // صور خاصة بكل لون: { "أبيض": [...], "أسود": [...] }. التطبيق
          // يستخدمها لما العميل يختار لون معين، ولو اللون المختار مش
          // موجود هنا يرجع لصورة الغلاف + الصور العامة.
          variantImages: colorImages,
          options,
          variants,
          specs,
          // آخر تعديل حقيقي على المنتج نفسه — يُستخدم مع updatedAt بتاع كل
          // variant عشان التطبيق يعرف يقارن بسرعة قبل ما يعتمد على الكاش.
          updatedAt: tmpl.write_date || null,
          // لمنتج بلا أي variants حقيقية (مقاس واحد/لون واحد فقط)، الستوك
          // بييجي من مجموع qty_available لكل الفاريانتس (غالبًا واحد بس).
          stock: variants.length ? totalStock : null,
        };

        return new Response(JSON.stringify({ ok: true, product }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      } catch (e) {
        return new Response(JSON.stringify({ ok: false, error: String(e) }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
    }


    // مسار إنشاء طلب بيع حقيقي في Odoo (sale.order) + تأكيده + إيميل التأكيد
    // التلقائي بتاع Odoo نفسه — مش مجرد إشعار، ده أوردر فعلي بيتسجل بالضبط
    // زي أي أوردر جاي من موقع Odoo مباشرة.
    if (url.pathname === "/odoo-create-order") {
      if (request.method !== "POST") {
        return new Response("Method not allowed", { status: 405, headers: corsHeaders });
      }
      try {
        const payload = await request.json();
        const customer = payload.customer || {};
        const items = Array.isArray(payload.items) ? payload.items : [];
        if (!customer.phone || !customer.name || !items.length) {
          return new Response(JSON.stringify({ ok: false, error: "missing customer or items" }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          });
        }

        const loginResp = await fetch(`${ODOO_URL}/jsonrpc`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            jsonrpc: "2.0",
            method: "call",
            params: {
              service: "common",
              method: "login",
              args: [ODOO_DB, ODOO_LOGIN, env.ODOO_API_KEY],
            },
          }),
        });
        const loginData = await loginResp.json();
        const uid = loginData.result;
        if (!uid) {
          return new Response(JSON.stringify({ ok: false, error: "Odoo login failed" }), {
            status: 401,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          });
        }

        const callKw = async (model, method, args, kwargs = {}) => {
          const resp = await fetch(`${ODOO_URL}/jsonrpc`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              jsonrpc: "2.0",
              method: "call",
              params: {
                service: "object",
                method: "execute_kw",
                args: [ODOO_DB, uid, env.ODOO_API_KEY, model, method, args, kwargs],
              },
            }),
          });
          const data = await resp.json();
          if (data.error) throw new Error(JSON.stringify(data.error));
          return data.result;
        };

        // خطوة 1: العميل — دوّر عليه برقم الهاتف الأول، لو مش موجود اعمله
        const existing = await callKw("res.partner", "search_read", [
          [["phone", "=", customer.phone]],
          ["id"],
        ], { limit: 1 });

        let partnerId;
        if (existing && existing.length) {
          partnerId = existing[0].id;
        } else {
          partnerId = await callKw("res.partner", "create", [{
            name: customer.name,
            phone: customer.phone,
            email: customer.email || false,
            street: customer.address || false,
          }]);
        }

        // خطوة 2: بناء سطور الطلب من نفس الـ SKU الحقيقي (product.product id)
        // اللي المستخدم اختاره فعليًا في صفحة المنتج — مفيش أي تخمين هنا.
        const orderLines = items.map((it) => [0, 0, {
          product_id: it.sku,
          product_uom_qty: it.qty,
          price_unit: it.price,
        }]);

        const paymentMethod = payload.paymentMethod === "bankak" || payload.paymentMethod === "fawry"
          ? payload.paymentMethod
          : "cod";
        const isElectronic = paymentMethod !== "cod";

        const orderId = await callKw("sale.order", "create", [{
          partner_id: partnerId,
          order_line: orderLines,
        }]);

        // خزّن توكن جهاز العميل (لو بعت واحد) عشان نقدر نبعتله إشعار Push
        // لما الطلب يتأكد فعليًا — الدفع الإلكتروني بس محتاج ده، الدفع
        // عند الاستلام بيتأكد فورًا فمش لازم إشعار لاحق.
        if (isElectronic && payload.fcmToken && env.ATEEM_KV) {
          try {
            await env.ATEEM_KV.put(`device:${orderId}`, payload.fcmToken, { expirationTtl: 60 * 60 * 24 * 14 });
          } catch (kvErr) {
            // best-effort — فشل التخزين مايأثرش على نجاح الطلب
          }
        }

        // نفس التوكن (لو موجود) بيتسجّل أيضًا بشكل دائم على رقم الهاتف —
        // ده مش خاص بهذا الطلب، ده اللي هيسمح لاحقًا بإشعارات استباقية
        // (سلة متروكة/تنبيه ذوق) حتى لو مفيش طلب مفتوح. كمان بنسجل وقت
        // هذا الطلب كـ "آخر طلب" للعميل، وبنمسح أي سلة متروكة مسجّلة له
        // بما إنه أكمل الشراء فعليًا — مفيش داعي نفكّره بسلة أكمل شراءها.
        if (env.ATEEM_KV) {
          const normPhone = normalizePhone(customer.phone);
          try {
            if (payload.fcmToken) {
              await env.ATEEM_KV.put(
                `device:phone:${normPhone}`,
                JSON.stringify({ fcmToken: payload.fcmToken, updatedAt: new Date().toISOString() })
              );
            }
            await env.ATEEM_KV.put(`lastorder:${normPhone}`, new Date().toISOString(), {
              expirationTtl: 60 * 60 * 24 * 60,
            });
            await env.ATEEM_KV.delete(`cart:${normPhone}`);
          } catch (kvErr) {
            // best-effort
          }
        }

        // خطوة 3: الدفع عند الاستلام يتأكد فورًا. الدفع الإلكتروني (بنكك/فوري)
        // يفضل "عرض سعر" غير مؤكَّد في Odoo لحد ما أحمد يتأكد يدويًا إن
        // المبلغ وصل فعلاً — التأكيد وقتها بييجي من رابط في رسالة تليجرام،
        // مش أوتوماتيك أبدًا.
        if (!isElectronic) {
          await callKw("sale.order", "action_confirm", [[orderId]]);
        }

        const orderInfo = await callKw("sale.order", "read", [[orderId], ["name", "amount_total"]]);
        const orderName = orderInfo && orderInfo[0] ? orderInfo[0].name : String(orderId);
         const orderTotal = orderInfo && orderInfo[0] ? orderInfo[0].amount_total : null;
const totalText = orderTotal != null ? orderTotal.toLocaleString('en-US') + ' SDG' : 'غير متاح';

        // خطوة 4: إيميل تأكيد Odoo التلقائي — بس للطلبات المؤكَّدة فورًا
        // (الدفع عند الاستلام). الدفع الإلكتروني ياخد إيميله بعد التأكيد
        // اليدوي عبر /odoo-confirm-order، مش دلوقتي.
        let emailSent = false;
        if (!isElectronic) {
          try {
            const templateRef = await callKw("ir.model.data", "search_read", [
              [["module", "=", "sale"], ["name", "=", "email_template_edi_sale"]],
              ["res_id"],
            ], { limit: 1 });
            if (templateRef && templateRef.length) {
              await callKw("mail.template", "send_mail", [
                templateRef[0].res_id, orderId,
              ], { force_send: true });
              emailSent = true;
            }
          } catch (emailErr) {
            emailSent = false;
          }
        }

        // إشعار تليجرام لفريق المتجر. للدفع الإلكتروني بيتضاف رابط تأكيد
        // بضغطة واحدة — يتفتح بعد ما أحمد يتأكد يدويًا إن المبلغ وصل فعلاً،
        // ووقتها بس بيتأكد الطلب ويتبعت إيميل Odoo وردّ تليجرام إنه اتأكد.
        try {
          if (env.TELEGRAM_BOT_TOKEN && env.TELEGRAM_CHAT_ID) {
            const itemsText = items.map((it) => `• ${it.name || it.sku} ${it.meta ? "(" + it.meta + ")" : ""} ×${it.qty}`).join("\n");
            const paymentLabel = paymentMethod === "bankak" ? "بنكك" : paymentMethod === "fawry" ? "فوري" : "عند الاستلام";
            let text =
              let text =
  (isElectronic ? "🕓 طلب جديد — بانتظار تأكيد وصول المبلغ\n\n" : "✅ طلب مؤكد فعليًا في Odoo\n\n") +
  `🧾 رقم الطلب: ${orderName}\n` +
  `💰 الإجمالي: ${totalText}\n` +
  `💳 طريقة الدفع: ${paymentLabel}\n` +
  `👤 الاسم: ${customer.name}\n` +
              `📞 الهاتف: ${customer.phone}\n` +
              (customer.address ? `📍 العنوان: ${customer.address}\n` : "") +
              `\n${itemsText}`;
            const tgBody = { chat_id: env.TELEGRAM_CHAT_ID, text };
            if (isElectronic) {
              // زرار Inline بـ callback_data بدل url: التأكيد بيحصل بضغطة
              // واحدة جوه تليجرام نفسه من غير ما يفتح أي نافذة/متصفح — وأهم
              // حاجة إن callback_data (على عكس الـ url) معندهوش Link Preview
              // تلقائي، فمفيش خطر إن الطلب يتأكد لوحده لمجرد إن تليجرام
              // "عاين" الرابط. التأكيد الفعلي لسه بيحصل بس لما أحمد يضغط.
              text += `\n\n✅ اضغط الزرار تحت بعد التأكد من وصول المبلغ فعليًا`;
              tgBody.text = text;
              tgBody.reply_markup = {
                inline_keyboard: [[{ text: "✅ تأكيد وصول المبلغ", callback_data: `confirm_order:${orderId}` }]],
              };
            }
            await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(tgBody),
            });
          }
        } catch (tgErr) {
          // إشعار داخلي بس — فشله مايأثرش على نجاح الطلب
        }

        return new Response(JSON.stringify({
          ok: true, orderId, orderName, emailSent,
          status: isElectronic ? "pending_payment_confirmation" : "confirmed",
        }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      } catch (e) {
        return new Response(JSON.stringify({ ok: false, error: String(e) }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
    }

    // مسار التأكيد اليدوي للدفع الإلكتروني — بيتفتح من رابط تليجرام بضغطة
    // واحدة، وبس بعد ما أحمد يتأكد بنفسه إن المبلغ وصل فعلاً في بنكك/فوري.
    // من هنا وبس من هنا يتحول الطلب لمؤكَّد فعليًا.
    if (url.pathname === "/odoo-confirm-order") {
      try {
        const orderId = parseInt(url.searchParams.get("id"), 10);
        const secret = url.searchParams.get("secret");
        if (!env.ORDER_CONFIRM_SECRET || secret !== env.ORDER_CONFIRM_SECRET) {
          return new Response("غير مصرّح", { status: 401, headers: corsHeaders });
        }

        const result = await confirmOdooOrder(env, orderId);
        if (!result.ok) {
          return new Response(result.message, { status: result.status || 500, headers: corsHeaders });
        }

        return new Response(
          `<!DOCTYPE html><html dir="rtl" lang="ar"><meta charset="utf-8">
          <body style="font-family:sans-serif;background:#F7F7F2;color:#292824;
          display:flex;align-items:center;justify-content:center;height:100vh;margin:0;">
          <div style="text-align:center;">
            <div style="font-size:48px;">✅</div>
            <h2>${result.alreadyConfirmed ? "الطلب مؤكد بالفعل" : "تم تأكيد الطلب"} ${result.orderName}</h2>
            <p style="color:#8A877F;">${
              result.alreadyConfirmed
                ? "الطلب اتأكد قبل كده، مفيش داعي لإعادة إرسال إشعارات."
                : (result.emailSent ? "وإرسال إيميل التأكيد للعميل" : "الطلب اتأكد، لكن إيميل التأكيد لم يُرسل — راجعه من Odoo")
            }</p>
          </div></body></html>`,
          { headers: { ...corsHeaders, "Content-Type": "text/html; charset=utf-8" } }
        );
      } catch (e) {
        return new Response("حصل خطأ: " + String(e), { status: 500, headers: corsHeaders });
      }
    }

    // Webhook تليجرام — بيستقبل ضغطات زرار "✅ تأكيد وصول المبلغ" اللي
    // بقت callback_data بدل رابط ويب. لازم يتسجل مرة واحدة بس عبر:
    //   https://api.telegram.org/bot<TOKEN>/setWebhook?url=<origin>/telegram-webhook&secret_token=<TELEGRAM_WEBHOOK_SECRET>
    // (TELEGRAM_WEBHOOK_SECRET سيكرت اختياري لكن بينصح بيه — تليجرام
    // بيرجّعه في هيدر X-Telegram-Bot-Api-Secret-Token مع كل تحديث، وده
    // بيتأكد بيه المسار إن الطلب فعلاً جاي من تليجرام مش من حد بيقلّده).
    if (url.pathname === "/telegram-webhook") {
      if (request.method !== "POST") {
        return new Response("Method not allowed", { status: 405, headers: corsHeaders });
      }
      try {
        if (env.TELEGRAM_WEBHOOK_SECRET) {
          const incomingSecret = request.headers.get("X-Telegram-Bot-Api-Secret-Token");
          if (incomingSecret !== env.TELEGRAM_WEBHOOK_SECRET) {
            return new Response("unauthorized", { status: 401, headers: corsHeaders });
          }
        }

        const update = await request.json();
        const cq = update.callback_query;
        // مش كل تحديث من تليجرام callback_query (ممكن يكون رسالة عادية،
        // إلخ) — لو مفيش، نرد 200 فاضي عشان تليجرام مايعتبروش فشل.
        if (!cq || !cq.data) {
          return new Response("ok", { headers: corsHeaders });
        }

        // بس المحادثة بتاعة صاحب المتجر (TELEGRAM_CHAT_ID) اللي تقدر تأكد
        // الطلبات — أي ضغطة جاية من شات تاني بترفض.
        if (env.TELEGRAM_CHAT_ID && String(cq.message?.chat?.id) !== String(env.TELEGRAM_CHAT_ID)) {
          await answerTelegramCallback(env, cq.id, "غير مصرّح", true);
          return new Response("ok", { headers: corsHeaders });
        }

        const match = /^confirm_order:(\d+)$/.exec(cq.data);
        if (!match) {
          await answerTelegramCallback(env, cq.id, "أمر غير معروف");
          return new Response("ok", { headers: corsHeaders });
        }
        const orderId = parseInt(match[1], 10);

        const result = await confirmOdooOrder(env, orderId);
        if (!result.ok) {
          await answerTelegramCallback(env, cq.id, result.message || "حصل خطأ", true);
          return new Response("ok", { headers: corsHeaders });
        }

        await answerTelegramCallback(
          env,
          cq.id,
          result.alreadyConfirmed ? "الطلب مؤكد بالفعل ✅" : "تم تأكيد الطلب ✅"
        );

        // نعدّل الرسالة الأصلية: نشيل الزرار (منعًا لضغط تاني) ونضيف سطر
        // تأكيد — كده أحمد شايف من نفس الرسالة إن الطلب اتقفل.
        if (cq.message) {
          try {
            const confirmedLine = result.alreadyConfirmed
              ? `\n\n✅ الطلب مؤكد بالفعل — رقم الطلب: ${result.orderName}`
              : `\n\n✅ تم التأكيد — رقم الطلب: ${result.orderName}`;
            await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/editMessageText`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                chat_id: cq.message.chat.id,
                message_id: cq.message.message_id,
                text: (cq.message.text || "") + confirmedLine,
              }),
            });
          } catch (editErr) {
            // best-effort — فشل تعديل الرسالة مايأثرش على نجاح التأكيد
          }
        }

        return new Response("ok", { headers: corsHeaders });
      } catch (e) {
        // تليجرام بيعيد المحاولة لو رجعنا خطأ — نرد 200 دايمًا هنا عشان
        // منغرقش في محاولات متكررة على نفس التحديث.
        return new Response("ok", { headers: corsHeaders });
      }
    }

    // المسار الافتراضي: بروكسي للشات (Groq)
    if (request.method !== "POST") {
      return new Response("Method not allowed", { status: 405, headers: corsHeaders });
    }
    try {
      const body = await request.text();
      const groqResp = await fetch("https://api.groq.com/openai/v1/chat/completions", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${env.GROQ_API_KEY}`,
        },
        body,
      });
      const data = await groqResp.text();
      return new Response(data, {
        status: groqResp.status,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    } catch (e) {
      return new Response(JSON.stringify({ error: String(e) }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
  },

  // نقطة دخول الـ Cron — بتتنادى تلقائيًا حسب جدول [triggers] crons في
  // wrangler.toml. ctx.waitUntil بيضمن إن الـ Worker يفضل شغال لحد ما
  // الفحصين يخلصوا حتى لو الاستجابة (اللي مفيش هنا أصلاً) خلصت قبلهم.
  async scheduled(event, env, ctx) {
    ctx.waitUntil(
      (async () => {
        await runAbandonedCartCheck(env);
        await runTasteAlertCheck(env);
      })()
    );
  },
};
