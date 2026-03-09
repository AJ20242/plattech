const THEME_KEY = 'vss-theme';

const themeToggle = document.getElementById('themeToggle');
const logoutBtn = document.getElementById('logoutBtn');
const ticketForm = document.getElementById('ticketForm');
const formMsg = document.getElementById('formMsg');
const subjectInput = document.getElementById('subjectInput');
const descriptionInput = document.getElementById('descriptionInput');
const priorityInput = document.getElementById('priorityInput');
const createTicketBtn = document.getElementById('createTicketBtn');
const ticketList = document.getElementById('ticketList');
const tickerList = document.getElementById('tickerList');

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

async function createTicket(payload) {
  const response = await fetch('/api/tickets', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify(payload)
  });
  const data = await response.json().catch(() => ({ message: 'Unexpected server response.' }));
  if (!response.ok) throw new Error(data.message || 'Failed to create ticket.');
  return data;
}

async function getMyTickets() {
  const response = await fetch('/api/tickets/my', { credentials: 'same-origin' });
  if (!response.ok) return { tickets: [] };
  return response.json();
}

async function updateTicketStatus(ticketId, status) {
  const response = await fetch(`/api/tickets/${encodeURIComponent(ticketId)}/status`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify({ status })
  });
  const data = await response.json().catch(() => ({ message: 'Unexpected server response.' }));
  if (!response.ok) throw new Error(data.message || 'Failed to update ticket status.');
  return data;
}

async function getBlockchainTicker() {
  const response = await fetch('/api/blockchain/ticker?limit=12', { credentials: 'same-origin' });
  if (!response.ok) return { events: [] };
  return response.json();
}

function renderTickets(data) {
  const items = data.tickets || [];
  if (items.length === 0) {
    ticketList.innerHTML = '<article class="ticket-item">No tickets yet.</article>';
    return;
  }
  ticketList.innerHTML = items
    .map(
      (t) => `
      <article class="ticket-item" data-ticket-id="${t.ticketId}">
        <h3>${t.subject}</h3>
        <p>${t.description}</p>
        <p class="ticket-meta">ID: ${t.ticketId} | Priority: ${t.priority} | Status: ${t.status}</p>
        <p class="ticket-meta">Created: ${new Date(t.createdAt).toLocaleString()}</p>
        <div class="status-row">
          <select class="status-select">
            <option value="open" ${t.status === 'open' ? 'selected' : ''}>Open</option>
            <option value="in_progress" ${t.status === 'in_progress' ? 'selected' : ''}>In Progress</option>
            <option value="resolved" ${t.status === 'resolved' ? 'selected' : ''}>Resolved</option>
          </select>
          <button class="status-save-btn" type="button">Save Status</button>
        </div>
      </article>
    `
    )
    .join('');
}

function renderTicker(data) {
  const events = data.events || [];
  if (events.length === 0) {
    tickerList.innerHTML = '<article class="ticker-item">No blockchain events yet.</article>';
    return;
  }
  tickerList.innerHTML = events
    .map(
      (event) => `
      <article class="ticker-item">
        <strong>${event.eventType}</strong>
        <p class="ticker-meta">${event.userEmail || '-'} | ${new Date(event.createdAt).toLocaleString()}</p>
        <code>${event.hash}</code>
      </article>
    `
    )
    .join('');
}

ticketForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  createTicketBtn.disabled = true;
  createTicketBtn.textContent = 'Creating...';
  formMsg.textContent = '';

  try {
    const payload = {
      subject: subjectInput.value.trim(),
      description: descriptionInput.value.trim(),
      priority: priorityInput.value
    };
    const result = await createTicket(payload);
    formMsg.textContent = `${result.message} (${result.ticketId})`;
    ticketForm.reset();
    priorityInput.value = 'medium';
    const [ticketsData, tickerData] = await Promise.all([getMyTickets(), getBlockchainTicker()]);
    renderTickets(ticketsData);
    renderTicker(tickerData);
  } catch (error) {
    formMsg.textContent = error.message || 'Failed to create ticket.';
  } finally {
    createTicketBtn.disabled = false;
    createTicketBtn.textContent = 'Create Ticket';
  }
});

ticketList.addEventListener('click', async (event) => {
  const btn = event.target.closest('.status-save-btn');
  if (!btn) return;
  const item = event.target.closest('.ticket-item');
  const ticketId = item?.dataset.ticketId;
  const select = item?.querySelector('.status-select');
  if (!ticketId || !select) return;

  btn.disabled = true;
  btn.textContent = 'Saving...';
  try {
    await updateTicketStatus(ticketId, select.value);
    const [ticketsData, tickerData] = await Promise.all([getMyTickets(), getBlockchainTicker()]);
    renderTickets(ticketsData);
    renderTicker(tickerData);
  } catch (error) {
    formMsg.textContent = error.message || 'Failed to update ticket.';
  } finally {
    btn.disabled = false;
    btn.textContent = 'Save Status';
  }
});

applyTheme(getPreferredTheme());
themeToggle.addEventListener('click', () => {
  const current = document.documentElement.getAttribute('data-theme') || 'light';
  const next = current === 'dark' ? 'light' : 'dark';
  applyTheme(next);
  localStorage.setItem(THEME_KEY, next);
});

logoutBtn.addEventListener('click', async () => {
  await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' });
  window.location.href = 'index.html';
});

(async () => {
  const user = await getCurrentUser();
  if (!user) {
    window.location.href = 'index.html';
    return;
  }
  const [ticketsData, tickerData] = await Promise.all([getMyTickets(), getBlockchainTicker()]);
  renderTickets(ticketsData);
  renderTicker(tickerData);
})();
