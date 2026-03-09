const THEME_KEY = 'vss-theme';

const themeToggle = document.getElementById('themeToggle');
const logoutBtn = document.getElementById('logoutBtn');
const welcomeText = document.getElementById('welcomeText');
const subText = document.getElementById('subText');
const adminLink = document.getElementById('adminLink');
const chainStatus = document.getElementById('chainStatus');
const auditList = document.getElementById('auditList');
const presentCountEl = document.getElementById('presentCount');
const lateCountEl = document.getElementById('lateCount');
const absentCountEl = document.getElementById('absentCount');
const notifBtn = document.getElementById('notifBtn');
const notifCount = document.getElementById('notifCount');
const notifPanel = document.getElementById('notifPanel');
const notifList = document.getElementById('notifList');
const notifToggle = document.getElementById('notifToggle');
const notifCounts = document.getElementById('notifCounts');
const notifHint = document.getElementById('notifHint');
let notificationsEnabled = false;
let notifRefreshTimer = null;

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
  const response = await fetch('/api/auth/me', {
    credentials: 'same-origin'
  });
  if (!response.ok) return null;
  return response.json();
}

async function getMyAudit() {
  const response = await fetch('/api/audit/my', {
    credentials: 'same-origin'
  });
  if (!response.ok) return null;
  return response.json();
}

async function getAttendanceSummary() {
  const response = await fetch('/api/attendance/summary', {
    credentials: 'same-origin'
  });
  if (!response.ok) return null;
  return response.json();
}

async function getNotifications() {
  const response = await fetch('/api/notifications', {
    credentials: 'same-origin'
  });
  const data = await response.json().catch(() => ({ message: 'Unexpected server response.' }));
  if (!response.ok) throw new Error(data.message || 'Failed to load notifications.');
  return data;
}

async function getNotificationSetting() {
  const response = await fetch('/api/settings/notifications', {
    credentials: 'same-origin'
  });
  if (!response.ok) return { enabled: false };
  return response.json();
}

async function setNotificationSetting(enabled) {
  const response = await fetch('/api/settings/notifications', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify({ enabled })
  });
  if (!response.ok) return { enabled: false };
  return response.json();
}

function renderAudit(audit) {
  if (!audit) {
    chainStatus.textContent = 'Audit records unavailable.';
    return;
  }

  chainStatus.textContent = audit.chainValid
    ? 'Chain integrity: Valid'
    : 'Chain integrity: Warning (tamper detected)';

  if (!audit.records || audit.records.length === 0) {
    auditList.innerHTML = '<article class="audit-item">No records yet.</article>';
    return;
  }

  auditList.innerHTML = audit.records
    .slice(-8)
    .reverse()
    .map(
      (record) => `
      <article class="audit-item">
        <strong>${record.eventType}</strong>
        <span class="meta">${new Date(record.createdAt).toLocaleString()}</span>
        <code>${record.entryHash}</code>
      </article>
    `
    )
    .join('');
}

function renderAttendance(summary) {
  if (!summary) return;
  presentCountEl.textContent = String(summary.present ?? 0);
  lateCountEl.textContent = String(summary.late ?? 0);
  absentCountEl.textContent = String(summary.absent ?? 0);
}

function renderNotifications(data) {
  if (!data || !notificationsEnabled) {
    notifCount.textContent = '0';
    notifCount.classList.add('hidden');
    notifCounts.textContent = 'Total reminders: 0 | Unread: 0';
    notifList.innerHTML = '<article class="notif-item"><p>Notifications are disabled.</p></article>';
    return;
  }
  const unread = Number(data.unreadReminders ?? data.unreadCount ?? 0);
  const total = Number(data.totalReminders ?? (Array.isArray(data.notifications) ? data.notifications.length : 0));
  notifCount.textContent = String(unread);
  notifCount.classList.toggle('hidden', unread <= 0);
  notifCounts.textContent = `Total reminders: ${total} | Unread: ${unread}`;

  const items = data.notifications || [];
  if (items.length === 0) {
    notifList.innerHTML = '<article class="notif-item"><p>No notifications.</p></article>';
    return;
  }

  notifList.innerHTML = items
    .map(
      (item) => `
      <article class="notif-item">
        <div class="notif-item-head">
          <strong>${item.title}</strong>
          <span class="notif-level ${item.level || 'info'}">${(item.level || 'info').replace('_', ' ')}</span>
        </div>
        <p>${item.message}</p>
        <p class="notif-time">${new Date(item.createdAt).toLocaleString()}</p>
        ${
          item.actionPath
            ? `<a class="notif-action-link" href="${item.actionPath}">${item.actionLabel || 'Open'}</a>`
            : ''
        }
      </article>
    `
    )
    .join('');
}

function showNotificationError(message) {
  notifList.innerHTML = `<article class="notif-item"><p>${message}</p></article>`;
}

function syncNotificationUI() {
  notifToggle.textContent = notificationsEnabled ? 'Disable' : 'Enable';
  notifHint.textContent = notificationsEnabled
    ? 'Notifications are enabled.'
    : 'Enable notifications to use this feature.';
  notifBtn.classList.toggle('is-disabled', !notificationsEnabled);
}

async function refreshNotifications() {
  if (!notificationsEnabled) {
    renderNotifications(null);
    return;
  }
  try {
    const notifications = await getNotifications();
    renderNotifications(notifications);
  } catch (error) {
    showNotificationError(error.message || 'Failed to load notifications.');
  }
}

function startNotificationPolling() {
  if (notifRefreshTimer) clearInterval(notifRefreshTimer);
  if (!notificationsEnabled) return;
  notifRefreshTimer = setInterval(() => {
    refreshNotifications().catch(() => {});
  }, 30000);
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

notifBtn.addEventListener('click', () => {
  const opening = notifPanel.classList.contains('hidden');
  notifPanel.classList.toggle('hidden');
  if (opening) {
    notifList.innerHTML = '<article class="notif-item"><p>Loading notifications...</p></article>';
    refreshNotifications().catch(() => {});
  }
});

document.addEventListener('click', (event) => {
  if (!notifPanel.classList.contains('hidden') && !event.target.closest('.notif-wrap')) {
    notifPanel.classList.add('hidden');
  }
});

notifToggle.addEventListener('click', async () => {
  const target = !notificationsEnabled;
  const result = await setNotificationSetting(target);
  notificationsEnabled = Boolean(result.enabled);
  syncNotificationUI();
  startNotificationPolling();
  await refreshNotifications();
});

(async () => {
  const currentUser = await getCurrentUser();
  if (!currentUser) {
    window.location.href = 'index.html';
    return;
  }

  welcomeText.textContent = `Welcome, ${currentUser.fullName}`;
  const roleLabel = String(currentUser.role || 'student');
  subText.textContent = `Signed in as ${currentUser.email} (${roleLabel})`;
  if (roleLabel === 'administrator') {
    adminLink.classList.remove('hidden');
    // Hide attendance cards for administrators
    const attendanceCards = document.getElementById('attendanceCards');
    if (attendanceCards) attendanceCards.classList.add('hidden');
  }

  const audit = await getMyAudit();
  renderAudit(audit);
  const attendance = await getAttendanceSummary();
  renderAttendance(attendance);
  const setting = await getNotificationSetting();
  notificationsEnabled = Boolean(setting.enabled);
  syncNotificationUI();
  startNotificationPolling();
  await refreshNotifications();
})();
