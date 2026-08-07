const API_BASE_URL = window.location.hostname === "seotaiji0324.github.io"
  ? "https://moa-member-signup.seotaiji0324.workers.dev"
  : "";
const SESSION_TOKEN_KEY = "moa_session_token";
const token = sessionStorage.getItem(SESSION_TOKEN_KEY);

const tableBody = document.querySelector("#member-table-body");
const emptyState = document.querySelector("#member-empty-state");
const adminStatus = document.querySelector("#admin-status");
const searchForm = document.querySelector("#member-search-form");
const searchInput = document.querySelector("#member-search");
const editDialog = document.querySelector("#edit-dialog");
const editForm = document.querySelector("#edit-form");
const editMessage = document.querySelector("#edit-status-message");
const usersById = new Map();

function apiUrl(path) {
  return `${API_BASE_URL}${path}`;
}

function returnToLogin() {
  sessionStorage.removeItem(SESSION_TOKEN_KEY);
  window.location.replace("index.html?login=required");
}

async function apiFetch(path, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set("Authorization", `Bearer ${sessionStorage.getItem(SESSION_TOKEN_KEY) || ""}`);
  const response = await fetch(apiUrl(path), { ...options, headers });
  if (response.status === 401 || response.status === 403) {
    returnToLogin();
    throw new Error("관리자 로그인이 필요합니다.");
  }
  return response;
}

function formatDate(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "-" : new Intl.DateTimeFormat("ko-KR", { dateStyle: "medium" }).format(date);
}

function cell(text, className = "") {
  const element = document.createElement("td");
  element.textContent = text;
  if (className) element.className = className;
  return element;
}

function renderUsers(users) {
  tableBody.replaceChildren();
  usersById.clear();
  emptyState.hidden = users.length > 0;

  for (const user of users) {
    usersById.set(user.id, user);
    const row = document.createElement("tr");

    const memberCell = document.createElement("td");
    const name = document.createElement("strong");
    const email = document.createElement("span");
    name.textContent = user.name;
    email.textContent = user.email;
    memberCell.className = "member-identity";
    memberCell.append(name, email);
    row.append(memberCell);

    const statusCell = document.createElement("td");
    const statusBadge = document.createElement("span");
    statusBadge.className = `status-badge status-${user.status}`;
    statusBadge.textContent = user.status === "active" ? "활성" : "정지";
    statusCell.append(statusBadge);
    row.append(statusCell);

    row.append(cell(user.role === "admin" ? "관리자" : "회원"));
    row.append(cell(formatDate(user.created_at)));

    const actions = document.createElement("td");
    actions.className = "row-actions";
    if (user.role === "admin") {
      const protectedLabel = document.createElement("span");
      protectedLabel.className = "protected-label";
      protectedLabel.textContent = "보호 계정";
      actions.append(protectedLabel);
    } else {
      const editButton = document.createElement("button");
      editButton.type = "button";
      editButton.dataset.action = "edit";
      editButton.dataset.id = user.id;
      editButton.textContent = "수정";

      const deleteButton = document.createElement("button");
      deleteButton.type = "button";
      deleteButton.dataset.action = "delete";
      deleteButton.dataset.id = user.id;
      deleteButton.className = "danger-action";
      deleteButton.textContent = "삭제";
      actions.append(editButton, deleteButton);
    }
    row.append(actions);
    tableBody.append(row);
  }
}

async function loadUsers() {
  adminStatus.textContent = "회원 정보를 불러오는 중입니다.";
  try {
    const query = searchInput.value.trim();
    const response = await apiFetch(`/api/admin/users?q=${encodeURIComponent(query)}`);
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.message || "회원 정보를 불러오지 못했습니다.");

    renderUsers(result.users || []);
    document.querySelector("#total-count").textContent = result.stats?.total ?? 0;
    document.querySelector("#active-count").textContent = result.stats?.active ?? 0;
    document.querySelector("#suspended-count").textContent = result.stats?.suspended ?? 0;
    adminStatus.textContent = query ? `검색 결과 ${result.users.length}명` : "";
  } catch (error) {
    adminStatus.textContent = error.message || "회원 정보를 불러오지 못했습니다.";
  }
}

function openEditDialog(user) {
  document.querySelector("#edit-id").value = user.id;
  document.querySelector("#edit-name").value = user.name;
  document.querySelector("#edit-email").value = user.email;
  document.querySelector("#edit-status").value = user.status;
  editMessage.textContent = "";
  editDialog.showModal();
  document.querySelector("#edit-name").focus();
}

tableBody.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-action]");
  if (!button) return;
  const user = usersById.get(button.dataset.id);
  if (!user) return;

  if (button.dataset.action === "edit") {
    openEditDialog(user);
    return;
  }

  if (!window.confirm(`${user.name} 회원을 삭제할까요? 이 작업은 되돌릴 수 없습니다.`)) return;
  button.disabled = true;
  try {
    const response = await apiFetch(`/api/admin/users/${user.id}`, { method: "DELETE" });
    if (!response.ok) {
      const result = await response.json().catch(() => ({}));
      throw new Error(result.message || "회원을 삭제하지 못했습니다.");
    }
    await loadUsers();
  } catch (error) {
    adminStatus.textContent = error.message || "회원을 삭제하지 못했습니다.";
  } finally {
    button.disabled = false;
  }
});

editForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  editMessage.textContent = "";
  const submitButton = editForm.querySelector("button[type='submit']");
  const id = document.querySelector("#edit-id").value;
  const payload = {
    name: document.querySelector("#edit-name").value.trim(),
    email: document.querySelector("#edit-email").value.trim(),
    status: document.querySelector("#edit-status").value,
  };

  if (!payload.name || !payload.email) {
    editMessage.textContent = "이름과 이메일을 입력해주세요.";
    return;
  }

  submitButton.disabled = true;
  try {
    const response = await apiFetch(`/api/admin/users/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.message || "회원정보를 수정하지 못했습니다.");
    editDialog.close();
    await loadUsers();
  } catch (error) {
    editMessage.textContent = error.message || "회원정보를 수정하지 못했습니다.";
  } finally {
    submitButton.disabled = false;
  }
});

document.querySelector("#edit-close-button").addEventListener("click", () => editDialog.close());
document.querySelector("#edit-cancel-button").addEventListener("click", () => editDialog.close());
document.querySelector("#refresh-button").addEventListener("click", loadUsers);
searchForm.addEventListener("submit", (event) => {
  event.preventDefault();
  loadUsers();
});

document.querySelector("#admin-logout-button").addEventListener("click", async () => {
  try {
    await apiFetch("/api/logout", { method: "POST" });
  } finally {
    returnToLogin();
  }
});

async function initializeAdmin() {
  if (!token) {
    returnToLogin();
    return;
  }

  const response = await apiFetch("/api/session");
  const result = await response.json().catch(() => ({}));
  if (!response.ok || result.user?.role !== "admin") {
    returnToLogin();
    return;
  }

  document.querySelector("#admin-identity").textContent = `${result.user.name} 관리자`;
  await loadUsers();
}

initializeAdmin().catch((error) => {
  adminStatus.textContent = error.message || "관리자 화면을 준비하지 못했습니다.";
});
