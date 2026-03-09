(function initFloatingChat() {
  const STORAGE_KEY = 'vss-float-chat-history';
  const MAX_ITEMS = 20;

  const host = document.createElement('div');
  host.className = 'vss-float-chat';
  host.innerHTML = `
    <button class="vss-chat-toggle" type="button" aria-label="Open AI chat" title="Open AI chat">AI</button>
    <section class="vss-chat-panel" aria-live="polite">
      <header class="vss-chat-head">
        <p class="vss-chat-title">AI Assistant</p>
        <button class="vss-chat-close" type="button" aria-label="Close chat">x</button>
      </header>
      <div class="vss-chat-messages"></div>
      <form class="vss-chat-form">
        <input class="vss-chat-input" type="text" placeholder="Ask anything..." required />
        <button class="vss-chat-send" type="submit">Send</button>
      </form>
    </section>
  `;

  document.body.appendChild(host);

  const toggleBtn = host.querySelector('.vss-chat-toggle');
  const panel = host.querySelector('.vss-chat-panel');
  const closeBtn = host.querySelector('.vss-chat-close');
  const messages = host.querySelector('.vss-chat-messages');
  const form = host.querySelector('.vss-chat-form');
  const input = host.querySelector('.vss-chat-input');
  const sendBtn = host.querySelector('.vss-chat-send');

  function loadHistory() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      const parsed = JSON.parse(raw || '[]');
      return Array.isArray(parsed) ? parsed.slice(-MAX_ITEMS) : [];
    } catch {
      return [];
    }
  }

  function saveHistory(items) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(items.slice(-MAX_ITEMS)));
  }

  let history = loadHistory();
  if (history.length === 0) {
    history = [{ role: 'bot', text: 'Hello. I am ready for open-ended questions.' }];
    saveHistory(history);
  }

  function appendMessage(role, text, persist = true) {
    const item = document.createElement('article');
    item.className = `vss-chat-msg ${role}`;
    item.textContent = text;
    messages.appendChild(item);
    messages.scrollTop = messages.scrollHeight;

    if (persist) {
      history.push({ role, text });
      history = history.slice(-MAX_ITEMS);
      saveHistory(history);
    }
  }

  history.forEach((entry) => appendMessage(entry.role, entry.text, false));

  function setOpen(open) {
    panel.classList.toggle('is-open', open);
    if (open) input.focus();
  }

  toggleBtn.addEventListener('click', () => {
    const open = !panel.classList.contains('is-open');
    setOpen(open);
  });

  closeBtn.addEventListener('click', () => setOpen(false));

  document.addEventListener('click', (event) => {
    if (!panel.classList.contains('is-open')) return;
    if (!host.contains(event.target)) setOpen(false);
  });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const text = input.value.trim();
    if (!text) return;

    appendMessage('user', text);
    input.value = '';
    sendBtn.disabled = true;
    sendBtn.textContent = '...';

    try {
      const response = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ message: text })
      });
      const data = await response.json().catch(() => ({ reply: 'Unexpected server response.' }));
      if (!response.ok) throw new Error(data.message || data.detail || 'Chat request failed.');
      appendMessage('bot', data.reply || 'No reply.');
    } catch (error) {
      appendMessage('bot', error.message || 'Unable to get AI response right now.');
    } finally {
      sendBtn.disabled = false;
      sendBtn.textContent = 'Send';
      input.focus();
    }
  });
})();
