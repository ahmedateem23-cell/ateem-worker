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

        // خطوة 3: الدفع عند الاستلام يتأكد فورًا. الدفع الإلكتروني (بنكك/فوري)
        // يفضل "عرض سعر" غير مؤكَّد في Odoo لحد ما أحمد يتأكد يدويًا إن
        // المبلغ وصل فعلاً — التأكيد وقتها بييجي من رابط في رسالة تليجرام،
        // مش أوتوماتيك أبدًا.
        if (!isElectronic) {
          await callKw("sale.order", "action_confirm", [[orderId]]);
        }

        const orderInfo = await callKw("sale.order", "read", [[orderId], ["name", "amount_total"]]);
        const orderName = orderInfo && orderInfo[0] ? orderInfo[0].name : String(orderId);

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
              (isElectronic ? "🕓 طلب جديد — بانتظار تأكيد وصول المبلغ\n\n" : "✅ طلب مؤكد فعليًا في Odoo\n\n") +
              `🧾 رقم الطلب: ${orderName}\n` +
              `💳 طريقة الدفع: ${paymentLabel}\n` +
              `👤 الاسم: ${customer.name}\n` +
              `📞 الهاتف: ${customer.phone}\n` +
              (customer.address ? `📍 العنوان: ${customer.address}\n` : "") +
              `\n${itemsText}`;
            const tgBody = { chat_id: env.TELEGRAM_CHAT_ID, text };
            if (isElectronic && env.ORDER_CONFIRM_SECRET) {
              // زرار Inline بدل رابط نصي: تليجرام بيعمل Link Preview تلقائي
              // لأي رابط نصي عادي في الرسالة (بيفتحه من السيرفر عشان يجيب
              // معاينة)، وده كان بيأكد الطلب أوتوماتيك من غير ما حد يضغط
              // فعليًا. الأزرار الـ Inline معندهاش معاينة تلقائية، فالتأكيد
              // بيحصل بس لما أحمد يضغط عليها فعلاً.
              text += `\n\n✅ اضغط الزرار تحت بعد التأكد من وصول المبلغ فعليًا`;
              tgBody.text = text;
              const confirmUrl = `${url.origin}/odoo-confirm-order?id=${orderId}&secret=${env.ORDER_CONFIRM_SECRET}`;
              tgBody.reply_markup = {
                inline_keyboard: [[{ text: "✅ تأكيد وصول المبلغ", url: confirmUrl }]],
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
        if (!orderId) {
          return new Response("رقم الطلب ناقص", { status: 400, headers: corsHeaders });
        }
        if (!env.ORDER_CONFIRM_SECRET || secret !== env.ORDER_CONFIRM_SECRET) {
          return new Response("غير مصرّح", { status: 401, headers: corsHeaders });
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
          return new Response("فشل تسجيل الدخول لـ Odoo", { status: 401, headers: corsHeaders });
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

        const before = await callKw("sale.order", "read", [[orderId], ["name", "state"]]);
        if (!before || !before.length) {
          return new Response("الطلب مش موجود", { status: 404, headers: corsHeaders });
        }
        const orderName = before[0].name;

        if (before[0].state !== "sale" && before[0].state !== "done") {
          await callKw("sale.order", "action_confirm", [[orderId]]);
        }

        let emailSent = false;
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
                text: `✅ تم تأكيد الدفع والطلب\n\n🧾 رقم الطلب: ${orderName}`,
              }),
            });
          }
        } catch (tgErr) {
          // best-effort
        }

        // إشعار Push للعميل نفسه إن طلبه اتأكد — التوكن بتاعه اتخزن وقت
        // إنشاء الطلب (لو الدفع إلكتروني وبعت توكن). فشل الإشعار مايأثرش
        // على نجاح التأكيد نفسه.
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


        return new Response(
          `<!DOCTYPE html><html dir="rtl" lang="ar"><meta charset="utf-8">
          <body style="font-family:sans-serif;background:#F7F7F2;color:#292824;
          display:flex;align-items:center;justify-content:center;height:100vh;margin:0;">
          <div style="text-align:center;">
            <div style="font-size:48px;">✅</div>
            <h2>تم تأكيد الطلب ${orderName}</h2>
            <p style="color:#8A877F;">${emailSent ? "وإرسال إيميل التأكيد للعميل" : "الطلب اتأكد، لكن إيميل التأكيد لم يُرسل — راجعه من Odoo"}</p>
          </div></body></html>`,
          { headers: { ...corsHeaders, "Content-Type": "text/html; charset=utf-8" } }
        );
      } catch (e) {
        return new Response("حصل خطأ: " + String(e), { status: 500, headers: corsHeaders });
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
};
