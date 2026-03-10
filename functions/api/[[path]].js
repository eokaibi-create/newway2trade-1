export async function onRequest(context) {
  try {
  const { request, env } = context;
  const url = new URL(request.url);
  const method = request.method.toUpperCase();
  const path = url.pathname.replace(/^\/api\/?/, "");
  const segments = path.split("/").filter(Boolean);

  const json = (status, data, headers = {}) => {
    return new Response(JSON.stringify(data), {
      status,
      headers: {
        "Content-Type": "application/json",
        ...headers
      }
    });
  };

  const readJson = async () => {
    try {
      return await request.json();
    } catch {
      return null;
    }
  };

  const now = () => new Date().toISOString();

  const getCookie = (name) => {
    const cookie = request.headers.get("Cookie") || "";
    const match = cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
    return match ? decodeURIComponent(match[1]) : null;
  };

  const setCookie = (name, value, opts = {}) => {
    const parts = [`${name}=${encodeURIComponent(value)}`];
    if (opts.maxAge) parts.push(`Max-Age=${opts.maxAge}`);
    parts.push("Path=/");
    parts.push("HttpOnly");
    parts.push("SameSite=Lax");
    parts.push("Secure");
    return parts.join("; ");
  };

  const randomToken = () => {
    const bytes = new Uint8Array(24);
    crypto.getRandomValues(bytes);
    return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };

  const hashPassword = async (password, salt, iterations = 120000) => {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
    const derived = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: enc.encode(salt),
        iterations,
        hash: "SHA-256"
      },
      key,
      256
    );
    const hash = btoa(String.fromCharCode(...new Uint8Array(derived)));
    return `pbkdf2$${iterations}$${salt}$${hash}`;
  };

  const verifyPassword = async (password, stored) => {
    if (!stored || !stored.startsWith("pbkdf2$")) return false;
    const [, iterStr, salt] = stored.split("$");
    const calc = await hashPassword(password, salt, Number(iterStr));
    return calc === stored;
  };

  const ensureSchema = async () => {
    await env.DB.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token TEXT UNIQUE NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS site_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        public INTEGER NOT NULL DEFAULT 0,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS category_i18n (
        category_id INTEGER NOT NULL,
        lang TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        PRIMARY KEY (category_id, lang)
      );
      CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sku TEXT,
        status TEXT NOT NULL,
        price TEXT,
        price_visible INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS product_i18n (
        product_id INTEGER NOT NULL,
        lang TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        PRIMARY KEY (product_id, lang)
      );
      CREATE TABLE IF NOT EXISTS product_variants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        product_id INTEGER NOT NULL,
        color TEXT,
        stock INTEGER
      );
      CREATE TABLE IF NOT EXISTS product_media (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        product_id INTEGER NOT NULL,
        media_key TEXT NOT NULL,
        sort_order INTEGER DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS customers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        company TEXT,
        email TEXT,
        phone TEXT,
        region TEXT,
        notes TEXT,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_name TEXT,
        customer_email TEXT,
        status TEXT,
        total TEXT,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS order_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL,
        product_id INTEGER,
        quantity INTEGER,
        price TEXT
      );
      CREATE TABLE IF NOT EXISTS contact_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT,
        message TEXT,
        created_at TEXT NOT NULL
      );
    `);

    const userCount = await env.DB.prepare("SELECT COUNT(*) as c FROM users").first();
    if (userCount && userCount.c === 0 && env.ADMIN_EMAIL && env.ADMIN_PASSWORD) {
      const salt = randomToken();
      const hash = await hashPassword(env.ADMIN_PASSWORD, salt);
      await env.DB.prepare(
        "INSERT INTO users (email, password_hash, role, status, created_at) VALUES (?, ?, ?, ?, ?)"
      ).bind(env.ADMIN_EMAIL, hash, "admin", "active", now()).run();
    }
  };

  const getSessionUser = async () => {
    const token = getCookie("ek_session");
    if (!token) return null;
    const session = await env.DB.prepare(
      "SELECT s.token, s.expires_at, u.id, u.email, u.role, u.status FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.token = ?"
    ).bind(token).first();
    if (!session) return null;
    if (new Date(session.expires_at) < new Date()) return null;
    return { id: session.id, email: session.email, role: session.role, status: session.status };
  };

  if (!env.DB) return json(500, { error: "DB binding missing" });
  await ensureSchema();

  if (segments[0] === "public" && segments[1] === "bootstrap") {
    const siteRow = await env.DB.prepare("SELECT value FROM site_settings WHERE key = 'i18n'").first();
    const i18n = siteRow ? JSON.parse(siteRow.value) : {};
    return json(200, { i18n });
  }

  if (segments[0] === "auth") {
    if (segments[1] === "login" && method === "POST") {
      const body = await readJson();
      if (!body || !body.email || !body.password) return json(400, { error: "invalid" });
      const user = await env.DB.prepare("SELECT * FROM users WHERE email = ? AND status = 'active'").bind(body.email).first();
      if (!user) return json(401, { error: "invalid" });
      const ok = await verifyPassword(body.password, user.password_hash);
      if (!ok) return json(401, { error: "invalid" });
      const token = randomToken();
      const expires = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();
      await env.DB.prepare("INSERT INTO sessions (user_id, token, expires_at, created_at) VALUES (?, ?, ?, ?)")
        .bind(user.id, token, expires, now()).run();
      return json(200, { user: { email: user.email, role: user.role } }, {
        "Set-Cookie": setCookie("ek_session", token, { maxAge: 7 * 24 * 3600 })
      });
    }
    if (segments[1] === "logout" && method === "POST") {
      const token = getCookie("ek_session");
      if (token) {
        await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
      }
      return json(200, { ok: true }, {
        "Set-Cookie": setCookie("ek_session", "", { maxAge: 0 })
      });
    }
    if (segments[1] === "me" && method === "GET") {
      const user = await getSessionUser();
      if (!user) return json(401, { error: "unauthorized" });
      return json(200, { user: { email: user.email, role: user.role } });
    }
  }

  if (segments[0] === "media" && method === "GET") {
    const key = segments.slice(1).join("/");
    if (!key) return new Response("Not found", { status: 404 });
    const obj = await env.MEDIA.get(key);
    if (!obj) return new Response("Not found", { status: 404 });
    const headers = new Headers();
    obj.writeHttpMetadata(headers);
    headers.set("Cache-Control", "public, max-age=86400");
    return new Response(obj.body, { headers });
  }

  if (segments[0] === "admin") {
    const user = await getSessionUser();
    if (!user || user.status !== "active") return json(401, { error: "unauthorized" });

    if (segments[1] === "site") {
      if (method === "GET") {
        const row = await env.DB.prepare("SELECT value FROM site_settings WHERE key = 'i18n'").first();
        return json(200, { i18n: row ? JSON.parse(row.value) : {} });
      }
      if (method === "PUT") {
        const body = await readJson();
        if (!body) return json(400, { error: "invalid" });
        await env.DB.prepare(
          "INSERT INTO site_settings (key, value, public, updated_at) VALUES ('i18n', ?, 1, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at"
        ).bind(JSON.stringify(body.i18n || {}), now()).run();
        return json(200, { ok: true });
      }
    }

    if (segments[1] === "products") {
      if (method === "GET") {
        const list = await env.DB.prepare("SELECT * FROM products ORDER BY id DESC").all();
        return json(200, { products: list.results || [] });
      }
      if (method === "POST") {
        const body = await readJson();
        if (!body) return json(400, { error: "invalid" });
        const res = await env.DB.prepare(
          "INSERT INTO products (sku, status, price, price_visible, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)"
        ).bind(body.sku || null, body.status || "draft", body.price || null, body.price_visible ? 1 : 0, now(), now()).run();
        return json(200, { id: res.meta.last_row_id });
      }
      if (segments[2]) {
        const productId = Number(segments[2]);
        if (Number.isNaN(productId)) return json(400, { error: "invalid" });
        if (method === "PUT") {
          const body = await readJson();
          if (!body) return json(400, { error: "invalid" });
          await env.DB.prepare(
            "UPDATE products SET sku = ?, status = ?, price = ?, price_visible = ?, updated_at = ? WHERE id = ?"
          ).bind(body.sku || null, body.status || "draft", body.price || null, body.price_visible ? 1 : 0, now(), productId).run();
          return json(200, { ok: true });
        }
        if (method === "DELETE") {
          await env.DB.prepare("DELETE FROM products WHERE id = ?").bind(productId).run();
          return json(200, { ok: true });
        }
      }
    }

    if (segments[1] === "media" && method === "POST") {
      const form = await request.formData();
      const file = form.get("file");
      if (!file) return json(400, { error: "missing" });
      const key = `uploads/${Date.now()}-${file.name}`;
      await env.MEDIA.put(key, file.stream(), { httpMetadata: { contentType: file.type } });
      return json(200, { key, url: `/api/media/${key}` });
    }

    if (segments[1] === "customers") {
      if (method === "GET") {
        const list = await env.DB.prepare("SELECT * FROM customers ORDER BY id DESC").all();
        return json(200, { customers: list.results || [] });
      }
      if (method === "POST") {
        const body = await readJson();
        if (!body) return json(400, { error: "invalid" });
        await env.DB.prepare(
          "INSERT INTO customers (name, company, email, phone, region, notes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
        ).bind(body.name || null, body.company || null, body.email || null, body.phone || null, body.region || null, body.notes || null, now()).run();
        return json(200, { ok: true });
      }
    }

    if (segments[1] === "orders") {
      if (method === "GET") {
        const list = await env.DB.prepare("SELECT * FROM orders ORDER BY id DESC").all();
        return json(200, { orders: list.results || [] });
      }
      if (method === "POST") {
        const body = await readJson();
        if (!body) return json(400, { error: "invalid" });
        await env.DB.prepare(
          "INSERT INTO orders (customer_name, customer_email, status, total, created_at) VALUES (?, ?, ?, ?, ?)"
        ).bind(body.customer_name || null, body.customer_email || null, body.status || "new", body.total || null, now()).run();
        return json(200, { ok: true });
      }
    }

    if (segments[1] === "contact") {
      if (method === "GET") {
        const list = await env.DB.prepare("SELECT * FROM contact_messages ORDER BY id DESC").all();
        return json(200, { messages: list.results || [] });
      }
    }
  }

  return json(404, { error: "not_found" });
  } catch (err) {
    return new Response(JSON.stringify({ error: "server_error", detail: String(err) }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}
