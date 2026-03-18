const THEME_KEY = "vss-theme";

const themeToggle = document.getElementById("themeToggle");
const logoutBtn = document.getElementById("logoutBtn");
const clearChatBtn = document.getElementById("clearChatBtn");
const voiceBtn = document.getElementById("voiceBtn");
const voiceState = document.getElementById("voiceState");
const userBadge = document.getElementById("userBadge");

const chatForm = document.getElementById("chatForm");
const chatText = document.getElementById("chatText");
const sendBtn = document.getElementById("sendBtn");
const chatMessages = document.getElementById("chatMessages");
const typingState = document.getElementById("typingState");

const quickButtons = document.querySelectorAll(".quick-btn");
const langBtn = document.getElementById("langBtn");

let currentVoiceLang = "en-US";
let recognition = null;
let isListening = false;
let currentUtterance = null;

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

async function getCurrentUser() {
  try {
    const response = await fetch("/api/auth/me", { credentials: "same-origin" });
    if (!response.ok) return null;
    return await response.json();
  } catch {
    return null;
  }
}

function escapeHtml(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function renderMessage(role, content) {
  const msg = document.createElement("div");
  msg.className = `msg ${role === "assistant" ? "bot" : "user"}`;
  msg.innerHTML = escapeHtml(content).replace(/\n/g, "<br>");
  chatMessages.appendChild(msg);
  chatMessages.scrollTop = chatMessages.scrollHeight;
}

function renderHistory(history) {
  chatMessages.innerHTML = "";
  (history || []).forEach((item) => {
    renderMessage(item.role, item.content);
  });
}

function setTyping(visible) {
  typingState.classList.toggle("hidden", !visible);
}

function setVoiceState(text = "", show = false) {
  voiceState.textContent = text;
  voiceState.classList.toggle("hidden", !show);
}

function setListeningUI(listening) {
  isListening = listening;
  if (voiceBtn) {
    voiceBtn.classList.toggle("is-listening", listening);
    voiceBtn.textContent = listening ? "Listening..." : "Voice";
    voiceBtn.setAttribute(
      "aria-label",
      listening ? "Stop voice input" : "Start voice input"
    );
  }
}

function stopSpeaking() {
  if ("speechSynthesis" in window) {
    window.speechSynthesis.cancel();
  }
  currentUtterance = null;
}

function speakText(text) {
  if (!("speechSynthesis" in window)) return;

  const cleanText = String(text || "").trim();
  if (!cleanText) return;

  window.speechSynthesis.cancel();

  const utterance = new SpeechSynthesisUtterance(cleanText);
  utterance.rate = 1;
  utterance.pitch = 1;
  utterance.volume = 1;

  const voices = window.speechSynthesis.getVoices();
  const englishVoice =
    voices.find(
      (v) =>
        /en/i.test(v.lang) &&
        /female|zira|aria|samantha|google us english/i.test(v.name)
    ) ||
    voices.find((v) => /en/i.test(v.lang)) ||
    null;

  if (englishVoice) utterance.voice = englishVoice;

  currentUtterance = utterance;
  window.speechSynthesis.speak(utterance);
}

async function loadHistory() {
  try {
    const response = await fetch("/api/chat/history", {
      credentials: "same-origin"
    });

    if (!response.ok) return;

    const data = await response.json();
    renderHistory(data.history || []);
  } catch (error) {
    console.error("Failed to load chat history:", error);
  }
}

async function sendMessage(message) {
  const text = String(message || "").trim();
  if (!text) return;

  renderMessage("user", text);
  chatText.value = "";
  sendBtn.disabled = true;
  setTyping(true);
  setVoiceState("", false);

  try {
    const response = await fetch("/api/chat", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      credentials: "same-origin",
      body: JSON.stringify({ message: text })
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      throw new Error(data.detail || data.message || "Chat request failed.");
    }

    const reply = String(data.reply || "").trim() || "No reply generated.";
    renderMessage("assistant", reply);
    speakText(reply);
  } catch (error) {
    renderMessage("assistant", error.message || "Chat request failed.");
  } finally {
    setTyping(false);
    sendBtn.disabled = false;
    chatText.focus();
  }
}

async function clearChat() {
  try {
    await fetch("/api/chat/history", {
      method: "DELETE",
      credentials: "same-origin"
    });
    await loadHistory();
    stopSpeaking();
    setVoiceState("Chat history cleared.", true);
    setTimeout(() => setVoiceState("", false), 1600);
  } catch (error) {
    setVoiceState("Failed to clear chat.", true);
  }
}

function setupVoiceRecognition() {
  const SpeechRecognition =
    window.SpeechRecognition || window.webkitSpeechRecognition;

  if (!SpeechRecognition) {
    if (voiceBtn) voiceBtn.disabled = true;
    if (langBtn) langBtn.disabled = true;
    setVoiceState("Voice input is not supported in this browser.", true);
    return;
  }

  recognition = new SpeechRecognition();
  recognition.lang = currentVoiceLang;
  recognition.interimResults = true;
  recognition.maxAlternatives = 1;
  recognition.continuous = false;

  let finalTranscript = "";

  recognition.onstart = () => {
    finalTranscript = "";
    setListeningUI(true);
    setVoiceState(
      currentVoiceLang === "fil-PH"
        ? "Listening... Maaari ka nang magsalita."
        : "Listening... Speak your question now.",
      true
    );
    stopSpeaking();
  };

  recognition.onresult = (event) => {
    let interimTranscript = "";

    for (let i = event.resultIndex; i < event.results.length; i++) {
      const transcript = event.results[i][0].transcript;
      if (event.results[i].isFinal) {
        finalTranscript += transcript + " ";
      } else {
        interimTranscript += transcript;
      }
    }

    const combined = `${finalTranscript}${interimTranscript}`.trim();
    chatText.value = combined;

    if (combined) {
      setVoiceState(`Heard: ${combined}`, true);
    }
  };

  recognition.onerror = (event) => {
    setListeningUI(false);

    if (event.error === "not-allowed") {
      setVoiceState("Microphone permission was denied.", true);
      return;
    }

    if (event.error === "no-speech") {
      setVoiceState("No speech detected. Try again.", true);
      return;
    }

    setVoiceState(`Voice error: ${event.error}`, true);
  };

  recognition.onend = () => {
    const finalText = chatText.value.trim();
    setListeningUI(false);

    if (finalText) {
      setVoiceState("Voice captured. Sending question...", true);
      sendMessage(finalText);
    } else {
      setVoiceState("Voice input stopped.", true);
    }
  };
}

function toggleVoiceInput() {
  if (!recognition) return;

  stopSpeaking();

  if (isListening) {
    recognition.stop();
    setVoiceState("Voice input stopped.", true);
    return;
  }

  try {
    recognition.lang = currentVoiceLang;
    recognition.start();
  } catch (error) {
    setVoiceState("Voice input is already active.", true);
  }
}

function handleQuickPrompt(prompt) {
  chatText.value = prompt;
  sendMessage(prompt);
}

function loadQuestionFromUrl() {
  const params = new URLSearchParams(window.location.search);
  const q = params.get("q");
  if (!q) return;
  chatText.value = q;
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

if (chatForm) {
  chatForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const text = chatText.value.trim();
    if (!text) return;
    await sendMessage(text);
  });
}

if (clearChatBtn) {
  clearChatBtn.addEventListener("click", clearChat);
}

if (voiceBtn) {
  voiceBtn.addEventListener("click", toggleVoiceInput);
}

if (langBtn) {
  langBtn.addEventListener("click", () => {
    if (currentVoiceLang === "en-US") {
      currentVoiceLang = "fil-PH";
      langBtn.textContent = "FIL";
      setVoiceState("Voice language set to Filipino / Taglish.", true);
    } else {
      currentVoiceLang = "en-US";
      langBtn.textContent = "ENG";
      setVoiceState("Voice language set to English.", true);
    }

    if (recognition) {
      recognition.lang = currentVoiceLang;
    }
  });
}

quickButtons.forEach((btn) => {
  btn.addEventListener("click", () => {
    const prompt = btn.dataset.prompt || btn.textContent || "";
    handleQuickPrompt(prompt);
  });
});

(async function initChatPage() {
  applyTheme(getPreferredTheme());
  setupVoiceRecognition();
  loadQuestionFromUrl();

  const user = await getCurrentUser();
  if (!user) {
    window.location.href = "index.html";
    return;
  }

  if (userBadge) {
    userBadge.textContent = `Signed in as ${user.fullName || user.email} (${user.role || "user"})`;
  }

  await loadHistory();
})();