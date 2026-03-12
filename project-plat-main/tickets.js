const THEME_KEY = "vss-theme";

const themeToggle = document.getElementById("themeToggle");
const logoutBtn = document.getElementById("logoutBtn");
const ticketForm = document.getElementById("ticketForm");
const formMsg = document.getElementById("formMsg");
const subjectInput = document.getElementById("subjectInput");
const descriptionInput = document.getElementById("descriptionInput");
const priorityInput = document.getElementById("priorityInput");
const createTicketBtn = document.getElementById("createTicketBtn");
const ticketList = document.getElementById("ticketList");
const tickerList = document.getElementById("tickerList");

const blockchainProofModal = document.getElementById("blockchainProofModal");
const proofTicket = document.getElementById("proofTicket");
const proofHash = document.getElementById("proofHash");
const proofTime = document.getElementById("proofTime");
const closeProof = document.getElementById("closeProof");

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
  const response = await fetch("/api/auth/me", { credentials: "same-origin" });
  if (!response.ok) return null;
  return response.json();
}

async function createTicket(payload) {
  const response = await fetch("/api/tickets", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify(payload),
  });

  let data = null;
  try {
    data = await response.json();
  } catch {
    data = { message: "Unexpected server response." };
  }

  if (!response.ok) {
    throw new Error(data?.detail || data?.message || "Failed to create ticket.");
  }

  return data || {};
}

async function getMyTickets() {
  const response = await fetch("/api/tickets/my", { credentials: "same-origin" });
  if (!response.ok) return { tickets: [] };
  return response.json();
}

async function updateTicketStatus(ticketId, status) {
  const response = await fetch(`/api/tickets/${encodeURIComponent(ticketId)}/status`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({ status }),
  });

  const data = await response.json().catch(() => ({ message: "Unexpected server response." }));

  if (!response.ok) {
    throw new Error(data.detail || data.message || "Failed to update ticket status.");
  }

  return data;
}

async function getBlockchainTicker() {
  const response = await fetch("/api/blockchain/ticker?limit=12", { credentials: "same-origin" });
  if (!response.ok) return { events: [] };
  return response.json();
}


async function verifyTicket(ticketId) {
  if (!blockchainProofModal || !proofTicket || !proofHash || !proofTime) {
    alert("Blockchain modal elements are missing in tickets.html");
    return;
  }

  try {
    const res = await fetch(`/api/blockchain/proof/${encodeURIComponent(ticketId)}`, {
      credentials: "same-origin",
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      alert(data.detail || data.message || "Blockchain proof not found.");
      return;
    }

    const proof = data.proof || {};

    proofTicket.textContent = proof.ticketId || proof.public_id || ticketId || "-";
    proofHash.textContent = proof.ticketHash || proof.ticket_hash || "-";

    const rawTime = proof.timestamp ?? proof.created_at ?? proof.updated_at;
    if (typeof rawTime === "number" && rawTime > 0) {
      proofTime.textContent = new Date(rawTime * 1000).toLocaleString();
    } else {
      proofTime.textContent = String(rawTime || "-");
    }

    blockchainProofModal.classList.remove("hidden");
  } catch (error) {
    console.error("Blockchain verification failed:", error);
    alert("Blockchain verification failed.");
  }
}

function renderTickets(data) {
  const items = data.tickets || [];

  if (!ticketList) return;

  if (items.length === 0) {
    ticketList.innerHTML = `<article class="ticket-item">No tickets yet.</article>`;
    return;
  }

  ticketList.innerHTML = items
    .map(
      (ticket) => `
      <article class="ticket-item" data-ticket-id="${ticket.ticketId}">
        <h3>${ticket.subject}</h3>
        <p>${ticket.description}</p>
        <p class="ticket-meta">ID: ${ticket.ticketId} | Priority: ${ticket.priority} | Status: ${ticket.status}</p>
        <p class="ticket-meta">Created: ${new Date(ticket.createdAt).toLocaleString()}</p>

        <div class="status-row">
          <select class="status-select">
            <option value="open" ${ticket.status === "open" ? "selected" : ""}>Open</option>
            <option value="in_progress" ${ticket.status === "in_progress" ? "selected" : ""}>In Progress</option>
            <option value="resolved" ${ticket.status === "resolved" ? "selected" : ""}>Resolved</option>
          </select>

          <button class="status-save-btn" type="button">Save Status</button>
          <button class="verify-btn" type="button" data-verify-ticket="${ticket.ticketId}">Verify on Blockchain</button>
        </div>
      </article>
    `
    )
    .join("");
}

function renderTicker(data) {
  const events = data.events || [];

  if (!tickerList) return;

  if (events.length === 0) {
    tickerList.innerHTML = `<article class="ticker-item">No blockchain events yet.</article>`;
    return;
  }

  tickerList.innerHTML = events
    .map(
      (event) => `
      <article class="ticker-item">
        <strong>${event.eventType}</strong>
        <p class="ticker-meta">${event.userEmail || "-"} | ${new Date(event.createdAt).toLocaleString()}</p>
        <code>${event.hash}</code>
      </article>
    `
    )
    .join("");
}

if (ticketForm) {
  ticketForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    createTicketBtn.disabled = true;
    createTicketBtn.textContent = "Creating...";
    formMsg.textContent = "";

    try {
      const payload = {
        subject: subjectInput.value.trim(),
        description: descriptionInput.value.trim(),
        priority: priorityInput.value,
      };

      const result = await createTicket(payload);

      const baseMessage = result?.message || "Ticket created successfully.";
      const ticketId = result?.ticketId ? ` (${result.ticketId})` : "";

      if (result?.blockchainError) {
        const chainMessage =
          typeof result.blockchainError === "string"
            ? result.blockchainError
            : result.blockchainError?.message || "Blockchain proof was not created.";

        formMsg.textContent = `${baseMessage}${ticketId} | Blockchain warning: ${chainMessage}`;
      } else {
        formMsg.textContent = `${baseMessage}${ticketId}`;
      }

      ticketForm.reset();
      priorityInput.value = "medium";

      const [ticketsData, tickerData] = await Promise.all([
        getMyTickets(),
        getBlockchainTicker(),
      ]);

      renderTickets(ticketsData || { tickets: [] });
      renderTicker(tickerData || { events: [] });
    } catch (error) {
      console.error("CREATE TICKET ERROR:", error);
      formMsg.textContent =
        error?.message || "Failed to create ticket.";
    } finally {
      createTicketBtn.disabled = false;
      createTicketBtn.textContent = "Create Ticket";
    }
  });
}

if (ticketList) {
  ticketList.addEventListener("click", async (event) => {
    const verifyBtn = event.target.closest("[data-verify-ticket]");
    if (verifyBtn) {
      const ticketId = verifyBtn.dataset.verifyTicket;
      if (ticketId) {
        await verifyTicket(ticketId);
      }
      return;
    }

    const saveBtn = event.target.closest(".status-save-btn");
    if (!saveBtn) return;

    const item = event.target.closest(".ticket-item");
    const ticketId = item?.dataset.ticketId;
    const select = item?.querySelector(".status-select");

    if (!ticketId || !select) return;

    saveBtn.disabled = true;
    saveBtn.textContent = "Saving...";

    try {
      await updateTicketStatus(ticketId, select.value);

      const [ticketsData, tickerData] = await Promise.all([
        getMyTickets(),
        getBlockchainTicker(),
      ]);

      renderTickets(ticketsData);
      renderTicker(tickerData);
    } catch (error) {
      formMsg.textContent = error.message || "Failed to update ticket.";
    } finally {
      saveBtn.disabled = false;
      saveBtn.textContent = "Save Status";
    }
  });
}

if (closeProof && blockchainProofModal) {
  closeProof.addEventListener("click", () => {
    blockchainProofModal.classList.add("hidden");
  });
}

if (blockchainProofModal) {
  blockchainProofModal.addEventListener("click", (event) => {
    if (event.target === blockchainProofModal) {
      blockchainProofModal.classList.add("hidden");
    }
  });
}

applyTheme(getPreferredTheme());

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
    await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" });
    window.location.href = "index.html";
  });
}

(async () => {
  const user = await getCurrentUser();
  if (!user) {
    window.location.href = "index.html";
    return;
  }

  const [ticketsData, tickerData] = await Promise.all([
    getMyTickets(),
    getBlockchainTicker(),
  ]);

  renderTickets(ticketsData);
  renderTicker(tickerData);
})();