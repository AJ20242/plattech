const THEME_KEY = 'vss-theme';

const themeToggle = document.getElementById('themeToggle');
const logoutBtn = document.getElementById('logoutBtn');
const userBadge = document.getElementById('userBadge');
const chatMessages = document.getElementById('chatMessages');
const chatForm = document.getElementById('chatForm');
const chatText = document.getElementById('chatText');
const voiceBtn = document.getElementById('voiceBtn');
const voiceState = document.getElementById('voiceState');
const sendBtn = document.getElementById('sendBtn');
const clearChatBtn = document.getElementById('clearChatBtn');
const typingState = document.getElementById('typingState');
const quickButtons = document.querySelectorAll('.quick-btn');
let historyPoll = null;
let lastHistorySignature = '';
let recognition = null;
let isListening = false;
const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;

function getPreferredTheme() {
  const saved = localStorage.getItem(THEME_KEY);
  if (saved === 'light' || saved === 'dark') return saved;
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  themeToggle.setAttribute('aria-label', theme === 'dark' ? 'Enable light mode' : 'Enable dark mode');
}

function appendMessage(role, text) {
  const item = document.createElement('article');
  item.className = `msg ${role === 'assistant' ? 'bot' : role}`;
  item.textContent = text;
  chatMessages.appendChild(item);
  chatMessages.scrollTop = chatMessages.scrollHeight;
}

function clearMessages() {
  chatMessages.innerHTML = '';
}

function historySignature(history) {
  return JSON.stringify(history || []);
}

async function getCurrentUser() {
  const response = await fetch('/api/auth/me', { credentials: 'same-origin' });
  if (!response.ok) return null;
  return response.json();
}

async function sendMessage(message) {
  const response = await fetch('/api/chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify({ message })
  });
  const data = await response.json().catch(() => ({ reply: 'Unexpected server response.' }));
  if (!response.ok) throw new Error(data.message || 'Chat request failed.');
  return data;
}

async function getChatHistory() {
  const response = await fetch('/api/chat/history', { credentials: 'same-origin' });
  const data = await response.json().catch(() => ({ history: [] }));
  if (!response.ok) throw new Error(data.message || 'Failed to load chat history.');
  return data.history || [];
}

async function clearChatHistory() {
  const response = await fetch('/api/chat/history', {
    method: 'DELETE',
    credentials: 'same-origin'
  });
  const data = await response.json().catch(() => ({ message: 'Failed to clear chat.' }));
  if (!response.ok) throw new Error(data.message || 'Failed to clear chat history.');
  return data;
}

function renderHistory(history) {
  clearMessages();
  const items = Array.isArray(history) ? history : [];
  if (items.length === 0) {
    appendMessage(
      'assistant',
      'Hello. I can handle open-ended conversations. Ask anything, and I will keep context across messages.'
    );
    return;
  }
  items.forEach((item) => appendMessage(item.role || 'assistant', item.content || ''));
  lastHistorySignature = historySignature(items);
}

async function syncHistory(force = false) {
  const history = await getChatHistory();
  const signature = historySignature(history);
  if (force || signature !== lastHistorySignature) {
    renderHistory(history);
  }
}

function startHistoryPolling() {
  if (historyPoll) clearInterval(historyPoll);
  historyPoll = setInterval(() => {
    syncHistory(false).catch(() => {});
  }, 4000);
}

function setVoiceState(message, isError = false) {
  if (!voiceState) return;
  if (!message) {
    voiceState.textContent = '';
    voiceState.classList.add('hidden');
    voiceState.style.color = '';
    return;
  }
  voiceState.textContent = message;
  voiceState.classList.remove('hidden');
  voiceState.style.color = isError ? '#ff9db0' : '';
}

function setVoiceButtonState(listening) {
  if (!voiceBtn) return;
  voiceBtn.textContent = listening ? 'Stop' : 'Voice';
  voiceBtn.classList.toggle('is-listening', listening);
  voiceBtn.setAttribute('aria-label', listening ? 'Stop voice input' : 'Start voice input');
}

function initSpeechRecognition() {
  if (!voiceBtn) return;
  if (!SpeechRecognition) {
    voiceBtn.disabled = true;
    voiceBtn.title = 'Voice input is not supported in this browser';
    return;
  }

  recognition = new SpeechRecognition();
  recognition.lang = 'en-US';
  recognition.interimResults = true;
  recognition.continuous = false;

  recognition.onstart = () => {
    isListening = true;
    setVoiceButtonState(true);
    setVoiceState('Listening...');
  };

  recognition.onresult = (event) => {
    let transcript = '';
    for (let i = event.resultIndex; i < event.results.length; i += 1) {
      transcript += event.results[i][0].transcript;
    }
    chatText.value = transcript.trim();
    if (chatText.value) setVoiceState('Voice captured. Edit if needed, then send.');
  };

  recognition.onerror = (event) => {
    const errCode = String(event.error || 'unknown');
    if (errCode === 'not-allowed') {
      setVoiceState('Microphone permission was denied.', true);
    } else {
      setVoiceState(`Voice input error: ${errCode}`, true);
    }
  };

  recognition.onend = () => {
    isListening = false;
    setVoiceButtonState(false);
    if (!chatText.value.trim()) {
      setVoiceState('');
      return;
    }
    chatText.focus();
  };

  voiceBtn.addEventListener('click', () => {
    if (!recognition) {
      setVoiceState('Voice input is not supported in this browser.', true);
      return;
    }
    if (isListening) {
      recognition.stop();
      return;
    }
    setVoiceState('');
    recognition.start();
  });
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

chatForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const message = chatText.value.trim();
  if (!message) return;

  appendMessage('user', message);
  chatText.value = '';
  sendBtn.disabled = true;
  sendBtn.textContent = 'Sending...';
  typingState.classList.remove('hidden');

  try {
    const result = await sendMessage(message);
    if (Array.isArray(result.history)) {
      renderHistory(result.history);
    } else {
      appendMessage('assistant', result.reply || 'No reply.');
    }
  } catch (error) {
    appendMessage('assistant', error.message || 'Unable to get AI response right now.');
  } finally {
    sendBtn.disabled = false;
    sendBtn.textContent = 'Send';
    typingState.classList.add('hidden');
    chatText.focus();
  }
});

clearChatBtn.addEventListener('click', async () => {
  clearChatBtn.disabled = true;
  clearChatBtn.textContent = 'Clearing...';
  try {
    await clearChatHistory();
    lastHistorySignature = '';
    renderHistory([]);
  } catch (error) {
    appendMessage('assistant', error.message || 'Failed to clear chat history.');
  } finally {
    clearChatBtn.disabled = false;
    clearChatBtn.textContent = 'Clear chat';
  }
});

quickButtons.forEach((btn) => {
  btn.addEventListener('click', () => {
    chatText.value = btn.dataset.prompt || '';
    chatText.focus();
  });
});

(async () => {
  initSpeechRecognition();
  const currentUser = await getCurrentUser();
  try {
    await syncHistory(true);
    startHistoryPolling();
  } catch (error) {
    renderHistory([]);
  }
  if (!currentUser) {
    userBadge.textContent = 'Guest mode';
    return;
  }
  userBadge.textContent = `Signed in as ${currentUser.email}`;
})();
