const THEME_KEY = "vss-theme";

const themeToggle = document.getElementById("themeToggle");
const logoutBtn = document.getElementById("logoutBtn");
const refreshBtn = document.getElementById("refreshBtn");
const adminEmail = document.getElementById("adminEmail");
const panelMessage = document.getElementById("panelMessage");

const totalUsers = document.getElementById("totalUsers");
const totalTickets = document.getElementById("totalTickets");
const openTickets = document.getElementById("openTickets");
const resolvedTickets = document.getElementById("resolvedTickets");

const usersTableBody = document.getElementById("usersTableBody");
const ticketsTableBody = document.getElementById("ticketsTableBody");
const auditTableBody = document.getElementById("auditTableBody");
const chainStatus = document.getElementById("chainStatus");

function getPreferredTheme() {
  const saved = localStorage.getItem(THEME_KEY);
  if (saved === "light" || saved === "dark") return saved;
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  if (themeToggle) {
    themeToggle.setAttribute(
      "aria-label",
      theme === "dark" ? "Enable light mode" : "Enable dark mode"
    );
  }
}

function setPanelMessage(message = "", isError = false) {
  if (!panelMessage) return;
  panelMessage.textContent = message;
  panelMessage.style.color = isError ? "#ff8ea1" : "";
}

async function getCurrentUser() {
  const response = await fetch("/api/auth/me", { credentials: "same-origin" });
  if (!response.ok) return null;
  return response.json();
}

async function getUsers() {
  const response = await fetch("/api/admin/users", { credentials: "same-origin" });
  const data = await response.json().catch(() => ({ users: [] }));
  if (!response.ok) throw new Error(data.detail || data.message || "Failed to load users.");
  return data;
}

async function getTickets() {
  const response = await fetch("/api/admin/tickets", { credentials: "same-origin" });
  const data = await response.json().catch(() => ({ tickets: [] }));
  if (!response.ok) throw new Error(data.detail || data.message || "Failed to load tickets.");
  return data;
}

async function getAudit() {
  const response = await fetch("/api/audit/admin/full", { credentials: "same-origin" });
  const data = await response.json().catch(() => ({ records: [], chainValid: false }));
  if (!response.ok) throw new Error(data.detail || data.message || "Failed to load audit logs.");
  return data;
}

async function updateUserRole(userId, role) {
  const response = await fetch(`/api/admin/users/${userId}/role`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({ role })
  });
  const data = await response.json().catch(() => ({ message: "Unexpected server response." }));
  if (!response.ok) throw new Error(data.detail || data.message || "Failed to update user role.");
  return data;
}

async function deleteUser(userId) {
  const response = await fetch(`/api/admin/users/${userId}`, {
    method: "DELETE",
    credentials: "same-origin"
  });
  const data = await response.json().catch(() => ({ message: "Unexpected server response." }));
  if (!response.ok) throw new Error(data.detail || data.message || "Failed to delete user.");
  return data;
}

async function updateTicketStatus(ticketId, status) {
  const response = await fetch(`/api/admin/tickets/${encodeURIComponent(ticketId)}/status`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({ status })
  });
  const data = await response.json().catch(() => ({ message: "Unexpected server response." }));
  if (!response.ok) throw new Error(data.detail || data.message || "Failed to update ticket status.");
  return data;
}

async function deleteTicket(ticketId) {
  const response = await fetch(`/api/admin/tickets/${encodeURIComponent(ticketId)}`, {
    method: "DELETE",
    credentials: "same-origin"
  });
  const data = await response.json().catch(() => ({ message: "Unexpected server response." }));
  if (!response.ok) throw new Error(data.detail || data.message || "Failed to delete ticket.");
  return data;
}

function prettyRole(role) {
  return String(role || "").replace(/\b\w/g, (m) => m.toUpperCase());
}

function prettyStatus(status) {
  return String(status || "").replace(/_/g, " ").replace(/\b\w/g, (m) => m.toUpperCase());
}

function renderStats(users, tickets) {
  totalUsers.textContent = String(users.length);
  totalTickets.textContent = String(tickets.length);
  openTickets.textContent = String(
    tickets.filter((t) => String(t.status).toLowerCase() !== "resolved").length
  );
  resolvedTickets.textContent = String(
    tickets.filter((t) => String(t.status).toLowerCase() === "resolved").length
  );
}

function renderUsers(users, currentUserEmail) {
  usersTableBody.innerHTML = users
    .map((user) => {
      const isSelf = String(user.email || "").toLowerCase() === String(currentUserEmail || "").toLowerCase();

      return `
        <tr data-user-id="${user.id}">
          <td>${user.id}</td>
          <td>${user.fullName || "-"}</td>
          <td>${user.email || "-"}</td>
          <td>
            <select class="role-select">
              <option value="student" ${user.role === "student" ? "selected" : ""}>Student</option>
              <option value="professor" ${user.role === "professor" ? "selected" : ""}>Professor</option>
              <option value="administrator" ${user.role === "administrator" ? "selected" : ""}>Administrator</option>
            </select>
          </td>
          <td>${user.createdAt ? new Date(user.createdAt).toLocaleString() : "-"}</td>
          <td>
            <div class="action-stack">
              <button class="save-user-btn" type="button">Save</button>
              <button
                class="danger-btn delete-user-btn"
                type="button"
                ${isSelf ? "disabled title='You cannot delete your own signed-in account.'" : ""}
              >
                Delete
              </button>
            </div>
          </td>
        </tr>
      `;
    })
    .join("");
}

function renderTickets(tickets) {
  ticketsTableBody.innerHTML = tickets
    .map(
      (ticket) => `
        <tr data-ticket-id="${ticket.ticketId}">
          <td>${ticket.ticketId}</td>
          <td>${ticket.userEmail || "-"}</td>
          <td>${ticket.subject || "-"}</td>
          <td>${prettyRole(ticket.priority)}</td>
          <td>
            <select class="ticket-status-select">
              <option value="open" ${ticket.status === "open" ? "selected" : ""}>Open</option>
              <option value="in_progress" ${ticket.status === "in_progress" ? "selected" : ""}>In Progress</option>
              <option value="resolved" ${ticket.status === "resolved" ? "selected" : ""}>Resolved</option>
            </select>
          </td>
          <td>${ticket.updatedAt ? new Date(ticket.updatedAt).toLocaleString() : "-"}</td>
          <td>
            <div class="action-stack">
              <button class="save-ticket-btn" type="button">Save</button>
              <button class="danger-btn delete-ticket-btn" type="button">Remove</button>
            </div>
          </td>
        </tr>
      `
    )
    .join("");
}

function renderAudit(audit) {
  chainStatus.textContent = audit.chainValid
    ? "Integrity status: VALID"
    : "Integrity status: INVALID (possible tampering)";

  auditTableBody.innerHTML = (audit.records || [])
    .slice(-40)
    .reverse()
    .map(
      (row) => `
        <tr>
          <td>${row.id}</td>
          <td title="${row.eventType || "-"}">${row.eventType || "-"}</td>
          <td title="${row.userEmail || "-"}">${row.userEmail || "-"}</td>
          <td>${row.createdAt ? new Date(row.createdAt).toLocaleString() : "-"}</td>
          <td title="${row.prevHash || "-"}">${row.prevHash || "-"}</td>
          <td title="${row.entryHash || "-"}">${row.entryHash || "-"}</td>
        </tr>
      `
    )
    .join("");
}

async function refreshAll() {
  setPanelMessage("Refreshing...");
  const user = await getCurrentUser();
  if (!user) {
    window.location.href = "index.html";
    return;
  }

  adminEmail.textContent = `Signed in as ${user.email}`;

  const [usersData, ticketsData, auditData] = await Promise.all([
    getUsers(),
    getTickets(),
    getAudit()
  ]);

  renderStats(usersData.users || [], ticketsData.tickets || []);
  renderUsers(usersData.users || [], user.email);
  renderTickets(ticketsData.tickets || []);
  renderAudit(auditData);

  setPanelMessage("Data refreshed.");
}

if (themeToggle) {
  themeToggle.addEventListener("click", () => {
    const current = document.documentElement.getAttribute("data-theme") || "light";
    const next = current === "dark" ? "light" : "dark";
    applyTheme(next);
    localStorage.setItem(THEME_KEY, next);
  });
}

if (logoutBtn) {
  logoutBtn.addEventListener("click", async () => {
    await fetch("/api/auth/logout", {
      method: "POST",
      credentials: "same-origin"
    });
    window.location.href = "index.html";
  });
}

if (refreshBtn) {
  refreshBtn.addEventListener("click", async () => {
    try {
      await refreshAll();
    } catch (error) {
      setPanelMessage(error.message || "Failed to refresh data.", true);
    }
  });
}

if (usersTableBody) {
  usersTableBody.addEventListener("click", async (event) => {
    const row = event.target.closest("tr");
    if (!row) return;

    const userId = row.dataset.userId;
    if (!userId) return;

    const saveBtn = event.target.closest(".save-user-btn");
    const deleteBtn = event.target.closest(".delete-user-btn");

    if (saveBtn) {
      const select = row.querySelector(".role-select");
      if (!select) return;

      saveBtn.disabled = true;
      saveBtn.textContent = "Saving...";

      try {
        await updateUserRole(userId, select.value);
        await refreshAll();
        setPanelMessage("User role updated.");
      } catch (error) {
        setPanelMessage(error.message || "Failed to update user role.", true);
      } finally {
        saveBtn.disabled = false;
        saveBtn.textContent = "Save";
      }
      return;
    }

    if (deleteBtn) {
      const emailCell = row.children[2]?.textContent?.trim() || "this user";
      const confirmed = window.confirm(`Delete account for ${emailCell}? This cannot be undone.`);
      if (!confirmed) return;

      deleteBtn.disabled = true;
      deleteBtn.textContent = "Deleting...";

      try {
        await deleteUser(userId);
        await refreshAll();
        setPanelMessage("User account deleted.");
      } catch (error) {
        setPanelMessage(error.message || "Failed to delete user.", true);
      } finally {
        deleteBtn.disabled = false;
        deleteBtn.textContent = "Delete";
      }
    }
  });
}

if (ticketsTableBody) {
  ticketsTableBody.addEventListener("click", async (event) => {
    const row = event.target.closest("tr");
    if (!row) return;

    const ticketId = row.dataset.ticketId;
    if (!ticketId) return;

    const saveBtn = event.target.closest(".save-ticket-btn");
    const deleteBtn = event.target.closest(".delete-ticket-btn");

    if (saveBtn) {
      const select = row.querySelector(".ticket-status-select");
      if (!select) return;

      saveBtn.disabled = true;
      saveBtn.textContent = "Saving...";

      try {
        await updateTicketStatus(ticketId, select.value);
        await refreshAll();
        setPanelMessage("Ticket status updated.");
      } catch (error) {
        setPanelMessage(error.message || "Failed to update ticket.", true);
      } finally {
        saveBtn.disabled = false;
        saveBtn.textContent = "Save";
      }
      return;
    }

    if (deleteBtn) {
      const confirmed = window.confirm(`Remove ticket ${ticketId}?`);
      if (!confirmed) return;

      deleteBtn.disabled = true;
      deleteBtn.textContent = "Removing...";

      try {
        await deleteTicket(ticketId);
        await refreshAll();
        setPanelMessage("Ticket removed.");
      } catch (error) {
        setPanelMessage(error.message || "Failed to delete ticket.", true);
      } finally {
        deleteBtn.disabled = false;
        deleteBtn.textContent = "Remove";
      }
    }
  });
}

applyTheme(getPreferredTheme());

(async () => {
  try {
    await refreshAll();
  } catch (error) {
    setPanelMessage(error.message || "Failed to load admin panel.", true);
  }
})();