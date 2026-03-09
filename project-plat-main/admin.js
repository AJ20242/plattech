const THEME_KEY = 'vss-theme';

const themeToggle = document.getElementById('themeToggle');
const logoutBtn = document.getElementById('logoutBtn');
const adminEmail = document.getElementById('adminEmail');
const chainStatus = document.getElementById('chainStatus');
const refreshBtn = document.getElementById('refreshBtn');
const panelMessage = document.getElementById('panelMessage');
const totalUsers = document.getElementById('totalUsers');
const totalTickets = document.getElementById('totalTickets');
const openTickets = document.getElementById('openTickets');
const resolvedTickets = document.getElementById('resolvedTickets');
const usersTableBody = document.getElementById('usersTableBody');
const ticketsTableBody = document.getElementById('ticketsTableBody');
const auditTableBody = document.getElementById('auditTableBody');

function getPreferredTheme() {
  const saved = localStorage.getItem(THEME_KEY);
  if (saved === 'light' || saved === 'dark') return saved;
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  themeToggle.setAttribute('aria-label', theme === 'dark' ? 'Enable light mode' : 'Enable dark mode');
}

async function getCurrentUser() {
  const response = await fetch('/api/auth/me', { credentials: 'same-origin' });
  if (!response.ok) return null;
  return response.json();
}

async function getFullAudit() {
  const response = await fetch('/api/audit/admin/full', { credentials: 'same-origin' });
  if (!response.ok) throw new Error('Admin access required.');
  return response.json();
}

async function getAdminUsers() {
  const response = await fetch('/api/admin/users', { credentials: 'same-origin' });
  const data = await response.json().catch(() => ({ message: 'Unexpected server response.' }));
  if (!response.ok) throw new Error(data.message || data.detail || 'Failed to load users.');
  return data.users || [];
}

async function getAdminTickets() {
  const response = await fetch('/api/admin/tickets', { credentials: 'same-origin' });
  const data = await response.json().catch(() => ({ message: 'Unexpected server response.' }));
  if (!response.ok) throw new Error(data.message || data.detail || 'Failed to load tickets.');
  return data.tickets || [];
}

async function updateUserRole(userId, role) {
  const response = await fetch(`/api/admin/users/${encodeURIComponent(userId)}/role`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify({ role })
  });
  const data = await response.json().catch(() => ({ message: 'Unexpected server response.' }));
  if (!response.ok) throw new Error(data.message || data.detail || 'Failed to update role.');
  return data;
}

async function updateTicketStatus(ticketId, status) {
  const response = await fetch(`/api/admin/tickets/${encodeURIComponent(ticketId)}/status`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify({ status })
  });
  const data = await response.json().catch(() => ({ message: 'Unexpected server response.' }));
  if (!response.ok) throw new Error(data.message || data.detail || 'Failed to update ticket status.');
  return data;
}

async function deleteTicket(ticketId) {
  try {
    const response = await fetch(`/api/admin/tickets/${encodeURIComponent(ticketId)}`, {
      method: 'DELETE',
      credentials: 'same-origin'
    });
    const text = await response.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch (e) {
      throw new Error(`Server error: ${text}`);
    }
    if (!response.ok) throw new Error(data.message || data.detail || 'Failed to delete ticket.');
    return data;
  } catch (e) {
    throw new Error(e.message || 'Failed to remove ticket.');
  }
}

function setPanelMessage(text, type = 'muted') {
  panelMessage.textContent = text;
  panelMessage.dataset.state = type;
}

function renderStats(users, tickets) {
  totalUsers.textContent = String(users.length);
  totalTickets.textContent = String(tickets.length);
  openTickets.textContent = String(tickets.filter((t) => t.status === 'open').length);
  resolvedTickets.textContent = String(tickets.filter((t) => t.status === 'resolved').length);
}

function renderUsers(users) {
  if (!users.length) {
    usersTableBody.innerHTML = '<tr><td colspan="6">No users found.</td></tr>';
    return;
  }
  usersTableBody.innerHTML = users
    .map(
      (u) => `
      <tr data-user-id="${u.id}">
        <td>${u.id}</td>
        <td>${u.fullName}</td>
        <td>${u.email}</td>
        <td>
          <select class="role-select">
            <option value="student" ${u.role === 'student' ? 'selected' : ''}>Student</option>
            <option value="professor" ${u.role === 'professor' ? 'selected' : ''}>Professor</option>
            <option value="administrator" ${u.role === 'administrator' ? 'selected' : ''}>Administrator</option>
          </select>
        </td>
        <td>${new Date(u.createdAt).toLocaleString()}</td>
        <td>
          <button class="save-role-btn" type="button">Save</button>
        </td>
      </tr>
    `
    )
    .join('');
}

function renderTickets(tickets) {
  if (!tickets.length) {
    ticketsTableBody.innerHTML = '<tr><td colspan="7">No tickets found.</td></tr>';
    return;
  }
  ticketsTableBody.innerHTML = tickets
    .map(
      (t) => `
      <tr data-ticket-id="${t.ticketId}">
        <td>${t.ticketId}</td>
        <td>${t.userEmail}</td>
        <td title="${t.description || ''}">${t.subject}</td>
        <td>${t.priority}</td>
        <td>
          <select class="status-select">
            <option value="open" ${t.status === 'open' ? 'selected' : ''}>Open</option>
            <option value="in_progress" ${t.status === 'in_progress' ? 'selected' : ''}>In Progress</option>
            <option value="resolved" ${t.status === 'resolved' ? 'selected' : ''}>Resolved</option>
          </select>
        </td>
        <td>${new Date(t.updatedAt).toLocaleString()}</td>
        <td><button class="save-ticket-btn" type="button">Save</button> <button class="remove-ticket-btn" type="button">Remove</button></td>
      </tr>
    `
    )
    .join('');
}

function renderAudit(data) {
  chainStatus.textContent = data.chainValid
    ? 'Integrity status: VALID'
    : 'Integrity status: INVALID (possible tampering)';

  if (!data.records || data.records.length === 0) {
    auditTableBody.innerHTML = '<tr><td colspan="6">No audit records found.</td></tr>';
    return;
  }

  auditTableBody.innerHTML = data.records
    .slice()
    .reverse()
    .map(
      (r) => `
      <tr>
        <td>${r.id}</td>
        <td>${r.eventType}</td>
        <td>${r.userEmail || '-'}</td>
        <td>${new Date(r.createdAt).toLocaleString()}</td>
        <td><code>${r.prevHash}</code></td>
        <td><code>${r.entryHash}</code></td>
      </tr>
    `
    )
    .join('');
}

async function loadAdminPanel() {
  setPanelMessage('Loading data...', 'muted');
  const [users, tickets, audit] = await Promise.all([getAdminUsers(), getAdminTickets(), getFullAudit()]);
  renderStats(users, tickets);
  renderUsers(users);
  renderTickets(tickets);
  renderAudit(audit);
  setPanelMessage('Data refreshed.', 'success');
}

applyTheme(getPreferredTheme());

themeToggle.addEventListener('click', () => {
  const current = document.documentElement.getAttribute('data-theme') || 'light';
  const next = current === 'dark' ? 'light' : 'dark';
  applyTheme(next);
  localStorage.setItem(THEME_KEY, next);
});

logoutBtn.addEventListener('click', async () => {
  await fetch('/api/auth/logout', {
    method: 'POST',
    credentials: 'same-origin'
  });
  window.location.href = 'index.html';
});

refreshBtn.addEventListener('click', async () => {
  refreshBtn.disabled = true;
  refreshBtn.textContent = 'Refreshing...';
  try {
    await loadAdminPanel();
  } catch (error) {
    setPanelMessage(error.message || 'Failed to refresh data.', 'error');
  } finally {
    refreshBtn.disabled = false;
    refreshBtn.textContent = 'Refresh Data';
  }
});

usersTableBody.addEventListener('click', async (event) => {
  const btn = event.target.closest('.save-role-btn');
  if (!btn) return;
  const row = event.target.closest('tr');
  const userId = row?.dataset.userId;
  const select = row?.querySelector('.role-select');
  if (!userId || !select) return;

  btn.disabled = true;
  btn.textContent = 'Saving...';
  try {
    await updateUserRole(userId, select.value);
    await loadAdminPanel();
  } catch (error) {
    setPanelMessage(error.message || 'Failed to update user role.', 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Save';
  }
});

ticketsTableBody.addEventListener('click', async (event) => {
  const saveBtn = event.target.closest('.save-ticket-btn');
  const deleteBtn = event.target.closest('.remove-ticket-btn');
  
  if (deleteBtn) {
    const row = event.target.closest('tr');
    const ticketId = row?.dataset.ticketId;
    if (!ticketId || !confirm('Are you sure you want to remove this ticket?')) return;
    
    deleteBtn.disabled = true;
    deleteBtn.textContent = 'Deleting...';
    try {
      await deleteTicket(ticketId);
      await loadAdminPanel();
    } catch (error) {
      setPanelMessage(error.message || 'Failed to remove ticket.', 'error');
    } finally {
      deleteBtn.disabled = false;
      deleteBtn.textContent = 'Remove';
    }
    return;
  }
  
  if (!saveBtn) return;
  const row = event.target.closest('tr');
  const ticketId = row?.dataset.ticketId;
  const select = row?.querySelector('.status-select');
  if (!ticketId || !select) return;

  saveBtn.disabled = true;
  saveBtn.textContent = 'Saving...';
  try {
    await updateTicketStatus(ticketId, select.value);
    await loadAdminPanel();
  } catch (error) {
    setPanelMessage(error.message || 'Failed to update ticket status.', 'error');
  } finally {
    saveBtn.disabled = false;
    saveBtn.textContent = 'Save';
  }
});

(async () => {
  const user = await getCurrentUser();
  if (!user) {
    window.location.href = 'index.html';
    return;
  }
  const isAdmin = user.role === 'administrator';
  if (!isAdmin) {
    window.location.href = 'dashboard.html';
    return;
  }
  adminEmail.textContent = `Signed in as ${user.email}`;

  try {
    await loadAdminPanel();
  } catch (error) {
    setPanelMessage(error.message || 'Access denied: admin only.', 'error');
  }
})();
