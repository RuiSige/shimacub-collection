
const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store"
  }
});

const error = (message, status = 400) =>
  json({ error: message }, status);

const encoder = new TextEncoder();

async function hash(value) {
  const bytes = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(value)
  );
  return [...new Uint8Array(bytes)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

const makeToken = () =>
  crypto.randomUUID() + "." + crypto.randomUUID();
// 復元コード：英数字12文字（4文字ごとに区切る）
const makeRecoveryCode = () => {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = new Uint8Array(12);
  crypto.getRandomValues(bytes);

  const code = [...bytes]
    .map(b => chars[b & 31])
    .join("");

  return code.match(/.{1,4}/g).join("-");
};

async function readBody(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

async function getUser(request, db) {
  const token = (request.headers.get("Authorization") || "")
    .replace(/^Bearer /, "");

  if (!token) return null;

  return db.prepare(
    "SELECT id, nickname FROM participants WHERE session_token_hash = ?"
  ).bind(await hash(token)).first();
}

async function getState(db, user) {
  const shops = (await db.prepare(
    "SELECT id, name, sort_order FROM shops WHERE active = 1 ORDER BY sort_order, id"
  ).all()).results;

  const owned = (await db.prepare(
    "SELECT shop_id FROM stamps WHERE participant_id = ?"
  ).bind(user.id).all()).results.map(row => row.shop_id);

  return {
    participant_id: user.id,
    nickname: user.nickname,
    shops,
    owned
  };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (!path.startsWith("/api/")) {
      return env.ASSETS.fetch(request);
    }

    try {
      const db = env.DB;

      if (path === "/api/health" && request.method === "GET") {
        const result = await db.prepare("SELECT 1 AS ok").first();
        return json({ status: "ok", database: result?.ok === 1 });
      }

      if (path === "/api/shops" && request.method === "GET") {
        const shops = (await db.prepare(
          "SELECT id, name, sort_order FROM shops WHERE active = 1 ORDER BY sort_order, id"
        ).all()).results;
        return json({ shops });
      }

      if (path === "/api/register" && request.method === "POST") {
        const body = await readBody(request);
        const nickname = String(body.nickname || "").trim();

        if (!nickname || nickname.length > 30) {
          return error("ニックネームは1〜30文字で入力してください");
        }

        const id = crypto.randomUUID();
        const session = makeToken();
        const recovery = makeRecoveryCode();

        await db.prepare(
          "INSERT INTO participants (id, nickname, session_token_hash, recovery_code_hash) VALUES (?, ?, ?, ?)"
        ).bind(
          id,
          nickname,
          await hash(session),
          await hash(recovery)
        ).run();

        return json({
          session,
          recovery,
          ...await getState(db, { id, nickname })
        });
      }

      if (path === "/api/recover" && request.method === "POST") {
        const body = await readBody(request);
        const code = String(body.recovery || "").trim();

        if (!/^[A-HJ-NP-Z2-9]{4}(-[A-HJ-NP-Z2-9]{4}){2}$/.test(code)) {
          return error("復元コードを確認してください");
        }

        const user = await db.prepare(
          "SELECT id, nickname FROM participants WHERE recovery_code_hash = ?"
        ).bind(await hash(code)).first();

        if (!user) {
          return error("復元コードが見つかりません", 404);
        }

        const session = makeToken();

        await db.prepare(
          "UPDATE participants SET session_token_hash = ? WHERE id = ?"
        ).bind(await hash(session), user.id).run();

        return json({
          session,
          ...await getState(db, user)
        });
      }

      const user = await getUser(request, db);

      if (!user) {
        return error("参加情報が見つかりません。復元コードを利用してください", 401);
      }

      if (path === "/api/me" && request.method === "GET") {
        return json(await getState(db, user));
      }

      // 登録情報の完全削除
      if (path === "/api/delete-account" && request.method === "POST") {
        const body = await readBody(request);

        if (body.confirm !== "DELETE") {
          return error("削除の確認が必要です");
        }

        // 所有記録と参加者情報を一括削除
        await db.batch([
          db.prepare(
            "DELETE FROM stamps WHERE participant_id = ?"
          ).bind(user.id),
          db.prepare(
            "DELETE FROM participants WHERE id = ?"
          ).bind(user.id)
        ]);

        return json({ ok: true });
      }

      if (path === "/api/toggle" && request.method === "POST") {
        const body = await readBody(request);
        const shopId = String(body.shop_id || "");

        const shop = await db.prepare(
          "SELECT id FROM shops WHERE id = ? AND active = 1"
        ).bind(shopId).first();

        if (!shop) {
          return error("店舗が見つかりません", 404);
        }

        const existing = await db.prepare(
          "SELECT id FROM stamps WHERE participant_id = ? AND shop_id = ?"
        ).bind(user.id, shopId).first();

        if (existing) {
          await db.prepare(
            "DELETE FROM stamps WHERE participant_id = ? AND shop_id = ?"
          ).bind(user.id, shopId).run();
        } else {
          await db.prepare(
            "INSERT OR IGNORE INTO stamps (participant_id, shop_id) VALUES (?, ?)"
          ).bind(user.id, shopId).run();
        }

        return json({
          ok: true,
          ...await getState(db, user)
        });
      }

      return error("ページが見つかりません", 404);

    } catch (e) {
      console.error(e);
      return error("サーバーでエラーが発生しました", 500);
    }
  }
};
