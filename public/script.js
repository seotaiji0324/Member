const form = document.querySelector("#signup-form");
const successCard = document.querySelector("#success-card");
const nameInput = document.querySelector("#name");
const emailInput = document.querySelector("#email");
const passwordInput = document.querySelector("#password");
const visibilityToggle = document.querySelector(".visibility-toggle");
const resetButton = document.querySelector("#reset-button");
const submitButton = form.querySelector(".submit-button");
const formStatus = document.querySelector("#form-status");
const loginDialog = document.querySelector("#login-dialog");
const loginForm = document.querySelector("#login-form");
const loginStatus = document.querySelector("#login-status");
const loginOpenButton = document.querySelector("#login-open-button");
const loginCloseButton = document.querySelector("#login-close-button");
const loginLink = document.querySelector("#login-link");
const logoutButton = document.querySelector("#logout-button");
const adminMenuLink = document.querySelector("#admin-menu-link");
const accountName = document.querySelector("#account-name");

const passwordRules = {
  length: (value) => value.length >= 10,
  letter: (value) => /[a-zA-Z]/.test(value),
  number: (value) => /\d/.test(value),
};

const PBKDF2_ITERATIONS = 210_000;
const API_BASE_URL = window.location.hostname === "seotaiji0324.github.io"
  ? "https://moa-member-signup.seotaiji0324.workers.dev"
  : "";
const SESSION_TOKEN_KEY = "moa_session_token";

function apiUrl(path) {
  return `${API_BASE_URL}${path}`;
}

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function derivePasswordProof(password, encodedSalt = "") {
  const salt = encodedSalt ? base64ToBytes(encodedSalt) : crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERATIONS },
    keyMaterial,
    256,
  );
  return {
    passwordProof: bytesToBase64(new Uint8Array(bits)),
    passwordSalt: encodedSalt || bytesToBase64(salt),
  };
}

function setError(input, message) {
  const field = input.closest(".field");
  const error = field.querySelector(".error");
  field.classList.toggle("invalid", Boolean(message));
  input.setAttribute("aria-invalid", String(Boolean(message)));
  error.textContent = message;
}

function validateName() {
  const value = nameInput.value.trim();
  setError(nameInput, value ? "" : "이름을 입력해주세요.");
  return Boolean(value);
}

function validateEmail() {
  const value = emailInput.value.trim();
  const isValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
  setError(emailInput, !value ? "이메일을 입력해주세요." : isValid ? "" : "올바른 이메일 형식을 입력해주세요.");
  return isValid;
}

function updatePasswordRules() {
  const value = passwordInput.value;
  Object.entries(passwordRules).forEach(([rule, test]) => {
    document.querySelector(`[data-rule="${rule}"]`).classList.toggle("met", test(value));
  });
}

function validatePassword() {
  const value = passwordInput.value;
  const isValid = Object.values(passwordRules).every((test) => test(value));
  setError(passwordInput, !value ? "비밀번호를 입력해주세요." : isValid ? "" : "비밀번호 조건을 모두 충족해주세요.");
  return isValid;
}

nameInput.addEventListener("blur", validateName);
emailInput.addEventListener("blur", validateEmail);
passwordInput.addEventListener("blur", validatePassword);

nameInput.addEventListener("input", () => {
  if (nameInput.closest(".field").classList.contains("invalid")) validateName();
});

emailInput.addEventListener("input", () => {
  if (emailInput.closest(".field").classList.contains("invalid")) validateEmail();
});

passwordInput.addEventListener("input", () => {
  updatePasswordRules();
  if (passwordInput.closest(".field").classList.contains("invalid")) validatePassword();
});

visibilityToggle.addEventListener("click", () => {
  const shouldShow = passwordInput.type === "password";
  passwordInput.type = shouldShow ? "text" : "password";
  visibilityToggle.setAttribute("aria-pressed", String(shouldShow));
  visibilityToggle.setAttribute("aria-label", shouldShow ? "비밀번호 숨기기" : "비밀번호 보기");
  passwordInput.focus();
});

function setSubmitting(isSubmitting) {
  submitButton.disabled = isSubmitting;
  submitButton.classList.toggle("loading", isSubmitting);
  submitButton.querySelector("span").textContent = isSubmitting ? "가입 중" : "가입하기";
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  formStatus.textContent = "";
  const valid = [validateName(), validateEmail(), validatePassword()].every(Boolean);

  if (!valid) {
    form.querySelector('[aria-invalid="true"]')?.focus();
    return;
  }

  setSubmitting(true);

  try {
    const passwordData = await derivePasswordProof(passwordInput.value);
    const response = await fetch(apiUrl("/api/signup"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: nameInput.value.trim(),
        email: emailInput.value.trim(),
        password: passwordInput.value,
        ...passwordData,
      }),
    });

    const result = await response.json().catch(() => ({}));

    if (!response.ok) {
      if (result.field === "email") setError(emailInput, result.message);
      else if (result.field === "password") setError(passwordInput, result.message);
      else if (result.field === "name") setError(nameInput, result.message);
      else formStatus.textContent = result.message || "가입 중 문제가 발생했습니다. 잠시 후 다시 시도해주세요.";
      form.querySelector('[aria-invalid="true"]')?.focus();
      return;
    }

    document.querySelector(".form-header").hidden = true;
    form.hidden = true;
    document.querySelector("#member-name").textContent = result.user?.name || nameInput.value.trim();
    successCard.hidden = false;
    resetButton.focus();
  } catch {
    formStatus.textContent = "서버에 연결할 수 없습니다. 네트워크 상태를 확인해주세요.";
  } finally {
    setSubmitting(false);
  }
});

resetButton.addEventListener("click", () => {
  form.reset();
  updatePasswordRules();
  document.querySelectorAll(".field").forEach((field) => field.classList.remove("invalid"));
  document.querySelectorAll(".error").forEach((error) => { error.textContent = ""; });
  formStatus.textContent = "";
  document.querySelector(".form-header").hidden = false;
  successCard.hidden = true;
  form.hidden = false;
  nameInput.focus();
});

function renderSession(user) {
  const loggedIn = Boolean(user);
  accountName.hidden = !loggedIn;
  accountName.textContent = user ? `${user.name}님` : "";
  loginOpenButton.hidden = loggedIn;
  logoutButton.hidden = !loggedIn;
  adminMenuLink.hidden = user?.role !== "admin";
}

function openLoginDialog(event) {
  event?.preventDefault();
  loginStatus.textContent = "";
  loginDialog.showModal();
  document.querySelector("#login-email").focus();
}

loginOpenButton.addEventListener("click", openLoginDialog);
loginLink.addEventListener("click", openLoginDialog);
loginCloseButton.addEventListener("click", () => loginDialog.close());

loginDialog.addEventListener("click", (event) => {
  if (event.target === loginDialog) loginDialog.close();
});

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  loginStatus.textContent = "";
  const email = document.querySelector("#login-email").value.trim();
  const password = document.querySelector("#login-password").value;
  const button = loginForm.querySelector("button[type='submit']");

  if (!email || !password) {
    loginStatus.textContent = "이메일과 비밀번호를 입력해주세요.";
    return;
  }

  button.disabled = true;
  button.querySelector("span").textContent = "확인 중";

  try {
    const challengeResponse = await fetch(apiUrl("/api/login/challenge"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });
    const challenge = await challengeResponse.json().catch(() => ({}));
    if (!challengeResponse.ok || !challenge.passwordSalt) throw new Error(challenge.message || "로그인 준비에 실패했습니다.");

    const { passwordProof } = await derivePasswordProof(password, challenge.passwordSalt);
    const response = await fetch(apiUrl("/api/login"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, passwordProof }),
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.message || "로그인하지 못했습니다.");

    sessionStorage.setItem(SESSION_TOKEN_KEY, result.token);
    renderSession(result.user);
    loginForm.reset();
    document.querySelector("#login-email").value = result.user.email;
    loginDialog.close();
  } catch (error) {
    loginStatus.textContent = error.message || "로그인 중 문제가 발생했습니다.";
  } finally {
    button.disabled = false;
    button.querySelector("span").textContent = "로그인";
  }
});

logoutButton.addEventListener("click", async () => {
  const token = sessionStorage.getItem(SESSION_TOKEN_KEY);
  sessionStorage.removeItem(SESSION_TOKEN_KEY);
  renderSession(null);
  if (!token) return;

  try {
    await fetch(apiUrl("/api/logout"), {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
  } catch {
    // 로컬 세션은 이미 제거되었으므로 별도 처리가 필요하지 않습니다.
  }
});

async function restoreSession() {
  const token = sessionStorage.getItem(SESSION_TOKEN_KEY);
  if (!token) {
    renderSession(null);
    return;
  }

  try {
    const response = await fetch(apiUrl("/api/session"), {
      headers: { Authorization: `Bearer ${token}` },
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error("session expired");
    renderSession(result.user);
  } catch {
    sessionStorage.removeItem(SESSION_TOKEN_KEY);
    renderSession(null);
  }
}

restoreSession().catch(() => renderSession(null));

if (new URLSearchParams(window.location.search).get("login") === "required") {
  openLoginDialog();
}
