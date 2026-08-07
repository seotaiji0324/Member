const JSON_HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store",
};

const PBKDF2_ITERATIONS = 210_000;
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PASSWORD_PROOF_PATTERN = /^[A-Za-z0-9+/]{43}=$/;
const PASSWORD_SALT_PATTERN = /^[A-Za-z0-9+/]{22}==$/;
const SESSION_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const GITHUB_PAGES_ORIGIN = "https://seotaiji0324.github.io";

function allowedCorsOrigin(request) {
  const origin = request.headers.get("Origin");
  if (!origin) return "";

  const requestOrigin = new URL(request.url).origin;
  return origin === requestOrigin || origin === GITHUB_PAGES_ORIGIN ? origin : null;
}

function withCors(response, origin) {
  if (!origin) return response;

  const headers = new Headers(response.headers);
  headers.set("Access-Control-Allow-Origin", origin);
  headers.append("Vary", "Origin");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function corsPreflight(origin) {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Authorization, Content-Type",
      "Access-Control-Max-Age": "86400",
      Vary: "Origin",
    },
  });
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
}

function methodNotAllowed(methods) {
  return new Response(null, { status: 405, headers: { Allow: methods.join(", ") } });
}

async function readJson(request, maxBytes = 4_096) {
  const contentType = request.headers.get("content-type") || "";
  if (!contentType.toLowerCase().startsWith("application/json")) {
    return { error: json({ message: "JSON 형식의 요청만 사용할 수 있습니다." }, 415) };
  }

  const contentLength = Number(request.headers.get("content-length") || 0);
  if (contentLength > maxBytes) {
    return { error: json({ message: "요청 데이터가 너무 큽니다." }, 413) };
  }

  try {
    return { value: await request.json() };
  } catch {
    return { error: json({ message: "요청 내용을 확인해주세요." }, 400) };
  }
}

function validateSignup(input) {
  const name = typeof input?.name === "string" ? input.name.trim() : "";
  const email = typeof input?.email === "string" ? input.email.trim().toLowerCase() : "";
  const password = typeof input?.password === "string" ? input.password : "";
  const passwordProof = typeof input?.passwordProof === "string" ? input.passwordProof : "";
  const passwordSalt = typeof input?.passwordSalt === "string" ? input.passwordSalt : "";

  if (!name || name.length > 50) {
    return { error: { field: "name", message: "이름은 1자 이상 50자 이하로 입력해주세요." } };
  }
  if (!email || email.length > 254 || !EMAIL_PATTERN.test(email)) {
    return { error: { field: "email", message: "올바른 이메일 형식을 입력해주세요." } };
  }
  if (password.length < 10 || password.length > 128 || !/[a-zA-Z]/.test(password) || !/\d/.test(password)) {
    return { error: { field: "password", message: "비밀번호는 10~128자이며 영문과 숫자를 포함해야 합니다." } };
  }
  if (!PASSWORD_PROOF_PATTERN.test(passwordProof) || !PASSWORD_SALT_PATTERN.test(passwordSalt)) {
    return { error: { field: "password", message: "비밀번호 보안 처리를 완료하지 못했습니다. 다시 시도해주세요." } };
  }

  return { value: { name, email, passwordProof, passwordSalt } };
}

function toBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function toBase64Url(bytes) {
  return toBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sha256Base64(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return toBase64(new Uint8Array(digest));
}

async function hashPasswordProof(passwordProof, passwordSalt) {
  const serverSalt = crypto.getRandomValues(new Uint8Array(16));
  const serverSaltBase64 = toBase64(serverSalt);
  const digest = await sha256Base64(`${passwordProof}:${serverSaltBase64}`);
  return `client-pbkdf2-sha256$${PBKDF2_ITERATIONS}$${passwordSalt}$${serverSaltBase64}$${digest}`;
}

function parsePasswordHash(passwordHash) {
  const [algorithm, iterations, clientSalt, serverSalt, digest] = String(passwordHash || "").split("$");
  if (
    algorithm !== "client-pbkdf2-sha256"
    || Number(iterations) !== PBKDF2_ITERATIONS
    || !PASSWORD_SALT_PATTERN.test(clientSalt || "")
    || !PASSWORD_SALT_PATTERN.test(serverSalt || "")
    || !PASSWORD_PROOF_PATTERN.test(digest || "")
  ) {
    return null;
  }
  return { clientSalt, serverSalt, digest };
}

async function verifyPasswordProof(passwordProof, passwordHash) {
  if (!PASSWORD_PROOF_PATTERN.test(passwordProof)) return false;
  const parsed = parsePasswordHash(passwordHash);
  if (!parsed) return false;

  const actual = fromBase64(await sha256Base64(`${passwordProof}:${parsed.serverSalt}`));
  const expected = fromBase64(parsed.digest);
  if (actual.byteLength !== expected.byteLength) return false;

  if (typeof crypto.subtle.timingSafeEqual === "function") {
    return crypto.subtle.timingSafeEqual(actual, expected);
  }

  let mismatch = 0;
  for (let index = 0; index < actual.length; index += 1) mismatch |= actual[index] ^ expected[index];
  return mismatch === 0;
}

async function createUser(request, env) {
  const input = await readJson(request);
  if (input.error) return input.error;

  const validation = validateSignup(input.value);
  if (validation.error) return json(validation.error, 400);

  const { name, email, passwordProof, passwordSalt } = validation.value;
  const id = crypto.randomUUID();
  const passwordHash = await hashPasswordProof(passwordProof, passwordSalt);
  const createdAt = new Date().toISOString();

  try {
    await env.DB.prepare(
      "INSERT INTO users (id, name, email, password_hash, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
    ).bind(id, name, email, passwordHash, createdAt).run();
  } catch (error) {
    if (String(error?.message || error).includes("UNIQUE constraint failed")) {
      return json({ field: "email", message: "이미 가입된 이메일입니다." }, 409);
    }
    console.error(JSON.stringify({ event: "signup_failed", error: "database_write_failed" }));
    return json({ message: "가입 정보를 저장하지 못했습니다. 잠시 후 다시 시도해주세요." }, 500);
  }

  return json({ user: { id, name, email, role: "member", createdAt } }, 201);
}

async function loginChallenge(request, env) {
  const input = await readJson(request, 1_024);
  if (input.error) return input.error;

  const email = typeof input.value?.email === "string" ? input.value.email.trim().toLowerCase() : "";
  if (!email || email.length > 254 || !EMAIL_PATTERN.test(email)) {
    return json({ message: "올바른 이메일을 입력해주세요." }, 400);
  }

  const user = await env.DB.prepare(
    "SELECT password_hash FROM users WHERE email = ?1 AND status = 'active' LIMIT 1",
  ).bind(email).first();
  const stored = parsePasswordHash(user?.password_hash);
  const fallbackSalt = toBase64(crypto.getRandomValues(new Uint8Array(16)));

  return json({ passwordSalt: stored?.clientSalt || fallbackSalt });
}

async function login(request, env) {
  const input = await readJson(request, 2_048);
  if (input.error) return input.error;

  const email = typeof input.value?.email === "string" ? input.value.email.trim().toLowerCase() : "";
  const passwordProof = typeof input.value?.passwordProof === "string" ? input.value.passwordProof : "";
  if (!email || !EMAIL_PATTERN.test(email) || !PASSWORD_PROOF_PATTERN.test(passwordProof)) {
    return json({ message: "이메일 또는 비밀번호가 올바르지 않습니다." }, 401);
  }

  const user = await env.DB.prepare(
    "SELECT id, name, email, password_hash, status, role FROM users WHERE email = ?1 LIMIT 1",
  ).bind(email).first();
  const valid = user?.status === "active" && await verifyPasswordProof(passwordProof, user?.password_hash);
  if (!valid) {
    return json({ message: "이메일 또는 비밀번호가 올바르지 않습니다." }, 401);
  }

  const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
  const token = toBase64Url(tokenBytes);
  const tokenHash = await sha256Base64(token);
  const createdAt = new Date();
  const expiresAt = new Date(createdAt.getTime() + SESSION_TTL_MS);

  await env.DB.batch([
    env.DB.prepare("DELETE FROM admin_sessions WHERE expires_at <= ?1").bind(createdAt.toISOString()),
    env.DB.prepare(
      "INSERT INTO admin_sessions (token_hash, user_id, expires_at, created_at) VALUES (?1, ?2, ?3, ?4)",
    ).bind(tokenHash, user.id, expiresAt.toISOString(), createdAt.toISOString()),
  ]);

  return json({
    token,
    expiresAt: expiresAt.toISOString(),
    user: { id: user.id, name: user.name, email: user.email, role: user.role },
  });
}

async function authenticate(request, env) {
  const authorization = request.headers.get("Authorization") || "";
  const match = authorization.match(/^Bearer ([A-Za-z0-9_-]{43})$/);
  if (!match || !SESSION_TOKEN_PATTERN.test(match[1])) return null;

  const tokenHash = await sha256Base64(match[1]);
  const now = new Date().toISOString();
  return env.DB.prepare(
    `SELECT u.id, u.name, u.email, u.role, u.status, s.token_hash, s.expires_at
     FROM admin_sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ?1 AND s.expires_at > ?2 AND u.status = 'active'
     LIMIT 1`,
  ).bind(tokenHash, now).first();
}

async function requireAdmin(request, env) {
  const user = await authenticate(request, env);
  if (!user) return { error: json({ message: "로그인이 필요합니다." }, 401) };
  if (user.role !== "admin") return { error: json({ message: "관리자 권한이 필요합니다." }, 403) };
  return { user };
}

async function sessionInfo(request, env) {
  const user = await authenticate(request, env);
  if (!user) return json({ message: "로그인이 필요합니다." }, 401);
  return json({ user: { id: user.id, name: user.name, email: user.email, role: user.role } });
}

async function logout(request, env) {
  const authorization = request.headers.get("Authorization") || "";
  const match = authorization.match(/^Bearer ([A-Za-z0-9_-]{43})$/);
  if (match) {
    const tokenHash = await sha256Base64(match[1]);
    await env.DB.prepare("DELETE FROM admin_sessions WHERE token_hash = ?1").bind(tokenHash).run();
  }
  return new Response(null, { status: 204, headers: { "Cache-Control": "no-store" } });
}

async function listUsers(request, env) {
  const authorization = await requireAdmin(request, env);
  if (authorization.error) return authorization.error;

  const query = new URL(request.url).searchParams.get("q")?.trim().slice(0, 100) || "";
  const search = `%${query}%`;
  const [usersResult, statsResult] = await env.DB.batch([
    env.DB.prepare(
      `SELECT id, name, email, status, role, created_at, updated_at
       FROM users
       WHERE (?1 = '' OR name LIKE ?2 OR email LIKE ?2)
       ORDER BY created_at DESC
       LIMIT 100`,
    ).bind(query, search),
    env.DB.prepare(
      `SELECT
         COUNT(*) AS total,
         SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) AS active,
         SUM(CASE WHEN status = 'suspended' THEN 1 ELSE 0 END) AS suspended
       FROM users`,
    ),
  ]);

  return json({
    users: usersResult.results || [],
    stats: statsResult.results?.[0] || { total: 0, active: 0, suspended: 0 },
  });
}

async function updateUser(request, env, userId) {
  const authorization = await requireAdmin(request, env);
  if (authorization.error) return authorization.error;

  const target = await env.DB.prepare("SELECT id, role FROM users WHERE id = ?1 LIMIT 1").bind(userId).first();
  if (!target) return json({ message: "회원을 찾을 수 없습니다." }, 404);
  if (target.role === "admin") return json({ message: "관리자 계정은 수정할 수 없습니다." }, 403);

  const input = await readJson(request, 2_048);
  if (input.error) return input.error;
  const name = typeof input.value?.name === "string" ? input.value.name.trim() : "";
  const email = typeof input.value?.email === "string" ? input.value.email.trim().toLowerCase() : "";
  const status = typeof input.value?.status === "string" ? input.value.status : "";

  if (!name || name.length > 50) return json({ field: "name", message: "이름은 1자 이상 50자 이하로 입력해주세요." }, 400);
  if (!email || email.length > 254 || !EMAIL_PATTERN.test(email)) return json({ field: "email", message: "올바른 이메일을 입력해주세요." }, 400);
  if (!new Set(["active", "suspended"]).has(status)) return json({ field: "status", message: "올바른 회원 상태를 선택해주세요." }, 400);

  const updatedAt = new Date().toISOString();
  try {
    await env.DB.prepare(
      "UPDATE users SET name = ?1, email = ?2, status = ?3, updated_at = ?4 WHERE id = ?5",
    ).bind(name, email, status, updatedAt, userId).run();
  } catch (error) {
    if (String(error?.message || error).includes("UNIQUE constraint failed")) {
      return json({ field: "email", message: "이미 사용 중인 이메일입니다." }, 409);
    }
    throw error;
  }

  return json({ user: { id: userId, name, email, status, updatedAt } });
}

async function deleteUser(request, env, userId) {
  const authorization = await requireAdmin(request, env);
  if (authorization.error) return authorization.error;

  const target = await env.DB.prepare("SELECT id, role FROM users WHERE id = ?1 LIMIT 1").bind(userId).first();
  if (!target) return json({ message: "회원을 찾을 수 없습니다." }, 404);
  if (target.role === "admin") return json({ message: "관리자 계정은 삭제할 수 없습니다." }, 403);

  await env.DB.batch([
    env.DB.prepare("DELETE FROM admin_sessions WHERE user_id = ?1").bind(userId),
    env.DB.prepare("DELETE FROM users WHERE id = ?1").bind(userId),
  ]);
  return new Response(null, { status: 204, headers: { "Cache-Control": "no-store" } });
}

async function routeApi(request, env, url) {
  if (url.pathname === "/api/signup") {
    if (request.method !== "POST") return methodNotAllowed(["POST"]);
    return createUser(request, env);
  }
  if (url.pathname === "/api/login/challenge") {
    if (request.method !== "POST") return methodNotAllowed(["POST"]);
    return loginChallenge(request, env);
  }
  if (url.pathname === "/api/login") {
    if (request.method !== "POST") return methodNotAllowed(["POST"]);
    return login(request, env);
  }
  if (url.pathname === "/api/logout") {
    if (request.method !== "POST") return methodNotAllowed(["POST"]);
    return logout(request, env);
  }
  if (url.pathname === "/api/session") {
    if (request.method !== "GET") return methodNotAllowed(["GET"]);
    return sessionInfo(request, env);
  }
  if (url.pathname === "/api/admin/users") {
    if (request.method !== "GET") return methodNotAllowed(["GET"]);
    return listUsers(request, env);
  }

  const userMatch = url.pathname.match(/^\/api\/admin\/users\/([0-9a-f-]{36})$/i);
  if (userMatch) {
    if (request.method === "PATCH") return updateUser(request, env, userMatch[1]);
    if (request.method === "DELETE") return deleteUser(request, env, userMatch[1]);
    return methodNotAllowed(["PATCH", "DELETE"]);
  }

  return json({ message: "API 경로를 찾을 수 없습니다." }, 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/")) {
      const requestOrigin = request.headers.get("Origin");
      const corsOrigin = allowedCorsOrigin(request);
      if (requestOrigin && !corsOrigin) return json({ message: "허용되지 않은 요청 출처입니다." }, 403);
      if (request.method === "OPTIONS") return corsPreflight(corsOrigin);

      try {
        return withCors(await routeApi(request, env, url), corsOrigin);
      } catch (error) {
        console.error(JSON.stringify({ event: "api_request_failed", path: url.pathname, error: String(error?.message || error) }));
        return withCors(json({ message: "요청을 처리하지 못했습니다. 잠시 후 다시 시도해주세요." }, 500), corsOrigin);
      }
    }

    return env.ASSETS.fetch(request);
  },
};

export { hashPasswordProof, parsePasswordHash, validateSignup, verifyPasswordProof };
