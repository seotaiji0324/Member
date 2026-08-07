const JSON_HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store",
};

const PBKDF2_ITERATIONS = 210_000;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
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
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Max-Age": "86400",
      Vary: "Origin",
    },
  });
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
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
  if (!/^[A-Za-z0-9+/]{43}=$/.test(passwordProof) || !/^[A-Za-z0-9+/]{22}==$/.test(passwordSalt)) {
    return { error: { field: "password", message: "비밀번호 보안 처리를 완료하지 못했습니다. 다시 시도해주세요." } };
  }

  return { value: { name, email, passwordProof, passwordSalt } };
}

function toBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

async function hashPasswordProof(passwordProof, passwordSalt) {
  const serverSalt = crypto.getRandomValues(new Uint8Array(16));
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(`${passwordProof}:${toBase64(serverSalt)}`),
  );
  return `client-pbkdf2-sha256$${PBKDF2_ITERATIONS}$${passwordSalt}$${toBase64(serverSalt)}$${toBase64(new Uint8Array(digest))}`;
}

async function createUser(request, env) {
  const contentType = request.headers.get("content-type") || "";
  if (!contentType.toLowerCase().startsWith("application/json")) {
    return json({ message: "JSON 형식의 요청만 사용할 수 있습니다." }, 415);
  }

  const contentLength = Number(request.headers.get("content-length") || 0);
  if (contentLength > 4_096) {
    return json({ message: "요청 데이터가 너무 큽니다." }, 413);
  }

  let input;
  try {
    input = await request.json();
  } catch {
    return json({ message: "요청 내용을 확인해주세요." }, 400);
  }

  const validation = validateSignup(input);
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

  return json({ user: { id, name, email, createdAt } }, 201);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/signup") {
      const requestOrigin = request.headers.get("Origin");
      const corsOrigin = allowedCorsOrigin(request);

      if (requestOrigin && !corsOrigin) {
        return json({ message: "허용되지 않은 요청 출처입니다." }, 403);
      }
      if (request.method === "OPTIONS") {
        return corsPreflight(corsOrigin);
      }
      if (request.method !== "POST") {
        return withCors(new Response(null, { status: 405, headers: { Allow: "POST" } }), corsOrigin);
      }
      return withCors(await createUser(request, env), corsOrigin);
    }

    return env.ASSETS.fetch(request);
  },
};

export { hashPasswordProof, validateSignup };
