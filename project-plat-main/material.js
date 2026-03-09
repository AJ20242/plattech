const THEME_KEY = 'vss-theme';

const themeToggle = document.getElementById('themeToggle');
const logoutBtn = document.getElementById('logoutBtn');
const userBadge = document.getElementById('userBadge');
const materialMsg = document.getElementById('materialMsg');
const materialForm = document.getElementById('materialForm');
const activityTitle = document.getElementById('activityTitle');
const activityDescription = document.getElementById('activityDescription');
const materialSubmitBtn = document.getElementById('materialSubmitBtn');
const activitiesList = document.getElementById('activitiesList');

// Quiz elements
const quizFormCard = document.getElementById('quizFormCard');
const quizMsg = document.getElementById('quizMsg');
const quizForm = document.getElementById('quizForm');
const quizTitle = document.getElementById('quizTitle');
const quizDescription = document.getElementById('quizDescription');
const quizType = document.getElementById('quizType');
const quizSubmitBtn = document.getElementById('quizSubmitBtn');
const quizList = document.getElementById('quizList');

// Exam elements
const examFormCard = document.getElementById('examFormCard');
const examMsg = document.getElementById('examMsg');
const examForm = document.getElementById('examForm');
const examTitle = document.getElementById('examTitle');
const examDescription = document.getElementById('examDescription');
const examSubmitBtn = document.getElementById('examSubmitBtn');
const examList = document.getElementById('examList');

function getPreferredTheme() {
  const saved = localStorage.getItem(THEME_KEY);
  if (saved === 'light' || saved === 'dark') return saved;
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  themeToggle.setAttribute('aria-label', theme === 'dark' ? 'Enable light mode' : 'Enable dark mode');
}

function setMessage(text, state = 'muted') {
  materialMsg.textContent = text;
  materialMsg.dataset.state = state;
}

async function getCurrentUser() {
  const response = await fetch('/api/auth/me', { credentials: 'same-origin' });
  if (!response.ok) return null;
  return response.json();
}

async function getActivities() {
  const response = await fetch('/api/material', { credentials: 'same-origin' });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.message || 'Failed to load activities.');
  return data.activities || [];
}

async function createActivity(title, description) {
  const response = await fetch('/api/material', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify({ title, description })
  });
  const raw = await response.text();
  let data = {};
  try {
    data = raw ? JSON.parse(raw) : {};
  } catch {
    data = { message: raw || `Server returned ${response.status}` };
  }
  if (!response.ok) throw new Error(data.message || `Failed to create activity (${response.status}).`);
  return data;
}

async function deleteActivity(id) {
  const response = await fetch(`/api/material/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    credentials: 'same-origin'
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.message || 'Failed to delete activity.');
  return data;
}

function renderActivities(activities, currentUserEmail) {
  if (!activities || activities.length === 0) {
    activitiesList.innerHTML = '<p class="empty-activities">No activities yet. Add one above.</p>';
    return;
  }
  activitiesList.innerHTML = activities
    .map(
      (a) => `
      <article class="activity-item" data-activity-id="${a.id}">
        <div class="activity-item-content">
          <h3>${escapeHtml(a.title)}</h3>
          ${a.description ? `<p>${escapeHtml(a.description)}</p>` : ''}
          <p class="activity-meta">By ${escapeHtml(a.createdByEmail)} · ${new Date(a.createdAt).toLocaleString()}</p>
        </div>
        ${
          currentUserEmail && a.createdByEmail === currentUserEmail
            ? `<div class="activity-item-actions"><button type="button" class="delete-activity-btn" data-id="${a.id}">Delete</button></div>`
            : ''
        }
      </article>
    `
    )
    .join('');
}

function escapeHtml(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

async function loadActivities() {
  setMessage('Loading...', 'muted');
  try {
    const activities = await getActivities();
    const user = await getCurrentUser();
    renderActivities(activities, user?.email || null);
    setMessage('');
  } catch (err) {
    setMessage(err.message || 'Failed to load activities.', 'error');
    activitiesList.innerHTML = '';
  }
}

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

materialForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const title = activityTitle.value.trim();
  const description = activityDescription.value.trim();
  if (!title) {
    setMessage('Title is required.', 'error');
    return;
  }
  materialSubmitBtn.disabled = true;
  materialSubmitBtn.textContent = 'Adding...';
  setMessage('');
  try {
    await createActivity(title, description);
    activityTitle.value = '';
    activityDescription.value = '';
    setMessage('Activity added.', 'success');
    await loadActivities();
  } catch (err) {
    setMessage(err.message || 'Failed to add activity.', 'error');
  } finally {
    materialSubmitBtn.disabled = false;
    materialSubmitBtn.textContent = 'Add Activity';
  }
});

activitiesList.addEventListener('click', async (e) => {
  const btn = e.target.closest('.delete-activity-btn');
  if (!btn) return;
  const id = btn.dataset.id;
  if (!id) return;
  if (!confirm('Delete this activity?')) return;
  btn.disabled = true;
  try {
    await deleteActivity(id);
    await loadActivities();
    setMessage('Activity deleted.', 'success');
  } catch (err) {
    setMessage(err.message || 'Failed to delete.', 'error');
  } finally {
    btn.disabled = false;
  }
});

// Quiz functions
async function getQuizzes() {
  const response = await fetch('/api/quiz', { credentials: 'same-origin' });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.message || 'Failed to load quizzes.');
  return data.quizzes || [];
}

async function createQuiz(title, description, quizType) {
  const response = await fetch('/api/quiz', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify({ title, description, quizType })
  });
  const raw = await response.text();
  let data = {};
  try {
    data = raw ? JSON.parse(raw) : {};
  } catch {
    data = { message: raw || `Server returned ${response.status}` };
  }
  if (!response.ok) throw new Error(data.message || `Failed to create quiz (${response.status}).`);
  return data;
}

async function deleteQuiz(id) {
  const response = await fetch(`/api/quiz/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    credentials: 'same-origin'
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.message || 'Failed to delete quiz.');
  return data;
}

function renderQuizzes(quizzes, currentUserEmail) {
  if (!quizzes || quizzes.length === 0) {
    quizList.innerHTML = '<p class="empty-quizzes">No quizzes/exams yet. Add one above.</p>';
    return;
  }
  quizList.innerHTML = quizzes
    .map(
      (q) => `
      <article class="quiz-item" data-quiz-id="${q.id}">
        <div class="quiz-item-content">
          <h3>${escapeHtml(q.title)} <span class="quiz-type-badge">${q.quizType === 'exam' ? 'Exam' : 'Quiz'}</span></h3>
          ${q.description ? `<p>${escapeHtml(q.description)}</p>` : ''}
          <p class="quiz-meta">By ${escapeHtml(q.createdByEmail)} · ${new Date(q.createdAt).toLocaleString()}</p>
        </div>
        ${
          currentUserEmail && q.createdByEmail === currentUserEmail
            ? `<div class="quiz-item-actions"><button type="button" class="delete-quiz-btn" data-id="${q.id}">Delete</button></div>`
            : ''
        }
      </article>
    `
    )
    .join('');
}

function setQuizMessage(text, state = 'muted') {
  quizMsg.textContent = text;
  quizMsg.dataset.state = state;
}

async function loadQuizzes() {
  setQuizMessage('Loading...', 'muted');
  try {
    const allQuizzes = await getQuizzes();
    const quizzes = allQuizzes.filter(q => q.quizType === 'quiz');
    const user = await getCurrentUser();
    renderQuizzes(quizzes, user?.email || null);
    setQuizMessage('');
  } catch (err) {
    setQuizMessage(err.message || 'Failed to load quizzes.', 'error');
    quizList.innerHTML = '';
  }
}

quizForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const title = quizTitle.value.trim();
  const description = quizDescription.value.trim();
  const type = quizType.value;
  if (!title) {
    setQuizMessage('Title is required.', 'error');
    return;
  }
  quizSubmitBtn.disabled = true;
  quizSubmitBtn.textContent = 'Adding...';
  setQuizMessage('');
  try {
    await createQuiz(title, description, type);
    quizTitle.value = '';
    quizDescription.value = '';
    setQuizMessage('Quiz/Exam added.', 'success');
    await loadQuizzes();
  } catch (err) {
    setQuizMessage(err.message || 'Failed to add quiz.', 'error');
  } finally {
    quizSubmitBtn.disabled = false;
    quizSubmitBtn.textContent = 'Add Quiz/Exam';
  }
});

quizList.addEventListener('click', async (e) => {
  const btn = e.target.closest('.delete-quiz-btn');
  if (!btn) return;
  const id = btn.dataset.id;
  if (!id) return;
  if (!confirm('Delete this quiz?')) return;
  btn.disabled = true;
  try {
    await deleteQuiz(id);
    await loadQuizzes();
    setQuizMessage('Quiz deleted.', 'success');
  } catch (err) {
    setQuizMessage(err.message || 'Failed to delete.', 'error');
  } finally {
    btn.disabled = false;
  }
});

// Exam functions
function renderExams(exams, currentUserEmail) {
  if (!exams || exams.length === 0) {
    examList.innerHTML = '<p class="empty-quizzes">No exams yet. Add one above.</p>';
    return;
  }
  examList.innerHTML = exams
    .map(
      (q) => `
      <article class="quiz-item" data-quiz-id="${q.id}">
        <div class="quiz-item-content">
          <h3>${escapeHtml(q.title)} <span class="quiz-type-badge exam">Exam</span></h3>
          ${q.description ? `<p>${escapeHtml(q.description)}</p>` : ''}
          <p class="quiz-meta">By ${escapeHtml(q.createdByEmail)} · ${new Date(q.createdAt).toLocaleString()}</p>
        </div>
        ${
          currentUserEmail && q.createdByEmail === currentUserEmail
            ? `<div class="quiz-item-actions"><button type="button" class="delete-quiz-btn" data-id="${q.id}">Delete</button></div>`
            : ''
        }
      </article>
    `
    )
    .join('');
}

function setExamMessage(text, state = 'muted') {
  examMsg.textContent = text;
  examMsg.dataset.state = state;
}

async function loadExams() {
  setExamMessage('Loading...', 'muted');
  try {
    const quizzes = await getQuizzes();
    const exams = quizzes.filter(q => q.quizType === 'exam');
    const user = await getCurrentUser();
    renderExams(exams, user?.email || null);
    setExamMessage('');
  } catch (err) {
    setExamMessage(err.message || 'Failed to load exams.', 'error');
    examList.innerHTML = '';
  }
}

examForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const title = examTitle.value.trim();
  const description = examDescription.value.trim();
  if (!title) {
    setExamMessage('Title is required.', 'error');
    return;
  }
  examSubmitBtn.disabled = true;
  examSubmitBtn.textContent = 'Adding...';
  setExamMessage('');
  try {
    await createQuiz(title, description, 'exam');
    examTitle.value = '';
    examDescription.value = '';
    setExamMessage('Exam added.', 'success');
    await loadExams();
  } catch (err) {
    setExamMessage(err.message || 'Failed to add exam.', 'error');
  } finally {
    examSubmitBtn.disabled = false;
    examSubmitBtn.textContent = 'Add Exam';
  }
});

(async () => {
  const user = await getCurrentUser();
  if (!user) {
    window.location.href = 'index.html';
    return;
  }
  const role = (user.role || '').toLowerCase();
  userBadge.textContent = `Signed in as ${user.email} (${user.role || 'student'})`;
  
  // Hide tabs for students - only professors can create content
  if (role === 'student') {
    const tabsEl = document.querySelector('.tabs');
    if (tabsEl) tabsEl.style.display = 'none';
    // Show all content for students (no tabs)
    document.querySelectorAll('.tab-content').forEach(el => el.classList.add('active'));
  }
  if (role === 'student') {
    const formCard = document.getElementById('materialFormCard');
    if (formCard) formCard.style.display = 'none';
    const quizFormCardEl = document.getElementById('quizFormCard');
    if (quizFormCardEl) quizFormCardEl.style.display = 'none';
    const examFormCardEl = document.getElementById('examFormCard');
    if (examFormCardEl) examFormCardEl.style.display = 'none';
  }
  await loadActivities();
  await loadQuizzes();
  await loadExams();
})();

// Tab switching
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    // Remove active class from all buttons and contents
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    
    // Add active class to clicked button
    btn.classList.add('active');
    
    // Show corresponding content
    const tabId = btn.dataset.tab;
    document.getElementById(`tab-${tabId}`).classList.add('active');
  });
});
