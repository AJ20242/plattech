const THEME_KEY = "vss-theme";

const themeToggle = document.getElementById("themeToggle");
const logoutBtn = document.getElementById("logoutBtn");
const userBadge = document.getElementById("userBadge");
const pageMessage = document.getElementById("pageMessage");

const typeTabs = document.querySelectorAll(".type-tab");
const professorBuilderCard = document.getElementById("professorBuilderCard");
const builderTitle = document.getElementById("builderTitle");
const listTitle = document.getElementById("listTitle");
const listHint = document.getElementById("listHint");

const builderForm = document.getElementById("builderForm");
const formTitle = document.getElementById("formTitle");
const formDescription = document.getElementById("formDescription");
const addShortAnswerBtn = document.getElementById("addShortAnswerBtn");
const addParagraphBtn = document.getElementById("addParagraphBtn");
const addMultipleChoiceBtn = document.getElementById("addMultipleChoiceBtn");
const builderQuestions = document.getElementById("builderQuestions");
const saveFormBtn = document.getElementById("saveFormBtn");

const formsList = document.getElementById("formsList");

const detailTitle = document.getElementById("detailTitle");
const detailHint = document.getElementById("detailHint");
const emptyDetail = document.getElementById("emptyDetail");
const detailCard = document.getElementById("detailCard");
const detailFormTitle = document.getElementById("detailFormTitle");
const detailDescription = document.getElementById("detailDescription");
const detailCreatedMeta = document.getElementById("detailCreatedMeta");

const studentAnswerForm = document.getElementById("studentAnswerForm");
const professorSubmissionPanel = document.getElementById("professorSubmissionPanel");
const submissionsList = document.getElementById("submissionsList");

const questionTemplate = document.getElementById("questionTemplate");

const studentScorePanel = document.getElementById("studentScorePanel");
const studentScoreValue = document.getElementById("studentScoreValue");
const studentSubmittedAt = document.getElementById("studentSubmittedAt");
const studentGradedAt = document.getElementById("studentGradedAt");
const studentFeedbackText = document.getElementById("studentFeedbackText");

let currentUser = null;
let currentKind = "activity";
let currentItems = [];
let selectedItem = null;

function renderStudentScorePanel(mySubmission) {
  if (!studentScorePanel) return;

  if (!mySubmission) {
    studentScorePanel.classList.add("hidden");
    return;
  }

  studentScorePanel.classList.remove("hidden");
  studentScoreValue.textContent =
    mySubmission.score !== null && mySubmission.score !== undefined
      ? String(mySubmission.score)
      : "Not graded";

  studentSubmittedAt.textContent = mySubmission.submittedAt
    ? formatDate(mySubmission.submittedAt)
    : "-";

  studentGradedAt.textContent = mySubmission.gradedAt
    ? formatDate(mySubmission.gradedAt)
    : "Not graded yet";

  studentFeedbackText.textContent =
    mySubmission.feedback && mySubmission.feedback.trim()
      ? mySubmission.feedback
      : "No feedback yet.";
}

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

function setPageMessage(message = "", isError = false) {
  pageMessage.textContent = message;
  pageMessage.className = `form-msg${isError ? " error" : ""}`;
}

function prettyKind(kind) {
  if (kind === "quiz") return "Quiz";
  if (kind === "exam") return "Exam";
  return "Activity";
}

function prettyType(type) {
  if (type === "short_answer") return "Short Answer";
  if (type === "paragraph") return "Paragraph";
  if (type === "multiple_choice") return "Multiple Choice";
  return type || "-";
}

function formatDate(value) {
  if (!value) return "-";
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

async function gradeSubmission(submissionId, payload) {
  return apiJson(`/api/forms/submissions/${encodeURIComponent(submissionId)}/grade`, {
    method: "PATCH",
    body: JSON.stringify(payload)
  });
}

async function getCurrentUser() {
  const response = await fetch("/api/auth/me", { credentials: "same-origin" });
  if (!response.ok) return null;
  return response.json();
}

async function apiJson(url, options = {}) {
  const response = await fetch(url, {
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {})
    },
    ...options
  });

  const data = await response.json().catch(() => ({
    message: "Unexpected server response."
  }));

  if (!response.ok) {
    throw new Error(data.detail || data.message || "Request failed.");
  }

  return data;
}

/*
  Expected backend routes for the next step:

  GET    /api/forms?kind=activity|quiz|exam
  POST   /api/forms
  GET    /api/forms/{form_id}
  DELETE /api/forms/{form_id}
  POST   /api/forms/{form_id}/submit
  GET    /api/forms/{form_id}/submissions
*/

async function fetchForms(kind) {
  return apiJson(`/api/forms?kind=${encodeURIComponent(kind)}`);
}

async function createForm(payload) {
  return apiJson("/api/forms", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

async function fetchFormDetail(formId) {
  return apiJson(`/api/forms/${encodeURIComponent(formId)}`);
}

async function deleteForm(formId) {
  return apiJson(`/api/forms/${encodeURIComponent(formId)}`, {
    method: "DELETE"
  });
}

async function submitFormAnswers(formId, payload) {
  return apiJson(`/api/forms/${encodeURIComponent(formId)}/submit`, {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

async function fetchSubmissions(formId) {
  return apiJson(`/api/forms/${encodeURIComponent(formId)}/submissions`);
}

function updateTitles() {
  const label = prettyKind(currentKind);
  builderTitle.textContent = `Create ${label}`;
  listTitle.textContent = `Published ${label}${currentKind === "activity" ? "s" : "s"}`;
  detailTitle.textContent = `${label} Details`;
  listHint.textContent =
    currentUser?.role === "professor"
      ? `Create, review, and manage ${label.toLowerCase()} items.`
      : `Open a ${label.toLowerCase()} and answer it.`;
}

function updateRoleUi() {
  const role = String(currentUser?.role || "").toLowerCase();
  const isProfessor = role === "professor";
  professorBuilderCard.classList.toggle("hidden", !isProfessor);

  userBadge.textContent = `Signed in as ${currentUser?.email || "-"} (${role || "user"})`;

  updateTitles();
}

function setActiveTab(kind) {
  currentKind = kind;
  typeTabs.forEach((tab) => {
    tab.classList.toggle("is-active", tab.dataset.kind === kind);
  });
  updateTitles();
}

function createQuestionBuilderCard(type = "short_answer") {
  const fragment = questionTemplate.content.cloneNode(true);
  const card = fragment.querySelector(".question-builder-card");
  const typeSelect = fragment.querySelector(".question-type");
  const choicesWrap = fragment.querySelector(".choices-wrap");
  const removeBtn = fragment.querySelector(".remove-question-btn");

  typeSelect.value = type;
  choicesWrap.classList.toggle("hidden", type !== "multiple_choice");

  typeSelect.addEventListener("change", () => {
    choicesWrap.classList.toggle("hidden", typeSelect.value !== "multiple_choice");
  });

  removeBtn.addEventListener("click", () => {
    card.remove();
    renumberQuestionCards();
  });

  builderQuestions.appendChild(fragment);
  renumberQuestionCards();
}

function renumberQuestionCards() {
  [...builderQuestions.querySelectorAll(".question-builder-card")].forEach((card, index) => {
    const badge = card.querySelector(".question-badge");
    if (badge) badge.textContent = `Question ${index + 1}`;
  });
}

function collectBuilderQuestions() {
  const cards = [...builderQuestions.querySelectorAll(".question-builder-card")];

  return cards.map((card) => {
    const type = card.querySelector(".question-type")?.value || "short_answer";
    const text = card.querySelector(".question-text")?.value.trim() || "";
    const required = card.querySelector(".question-required")?.checked || false;
    const rawChoices = card.querySelector(".question-choices")?.value || "";

    return {
      question: text,
      type,
      required,
      choices:
        type === "multiple_choice"
          ? rawChoices
              .split("\n")
              .map((item) => item.trim())
              .filter(Boolean)
          : []
    };
  });
}

function resetBuilder() {
  builderForm.reset();
  builderQuestions.innerHTML = "";
  createQuestionBuilderCard("short_answer");
}

function renderFormsList(items) {
  currentItems = items || [];

  if (!currentItems.length) {
    formsList.innerHTML = `<article class="empty-state">No ${currentKind}s published yet.</article>`;
    return;
  }

  const isProfessor = String(currentUser?.role || "").toLowerCase() === "professor";

  formsList.innerHTML = currentItems
    .map(
      (item) => `
        <article class="form-list-item ${selectedItem?.id === item.id ? "is-selected" : ""}" data-form-id="${item.id}">
          <div class="form-list-main">
            <h3>${item.title || "-"}</h3>
            <p>${item.description || "-"}</p>
            <p class="muted">By ${item.createdByEmail || "-"} · ${formatDate(item.createdAt)}</p>
          </div>
          <div class="form-list-actions">
            <button class="secondary-btn open-form-btn" type="button">Open</button>
            ${
              isProfessor
                ? `<button class="danger-btn delete-form-btn" type="button">Delete</button>`
                : ""
            }
          </div>
        </article>
      `
    )
    .join("");
}

async function openForm(formId) {
  const detail = await fetchFormDetail(formId);
  selectedItem = detail;

  emptyDetail.classList.add("hidden");
  detailCard.classList.remove("hidden");

  detailFormTitle.textContent = detail.title || "-";
  detailDescription.textContent = detail.description || "-";
  detailCreatedMeta.textContent = `By ${detail.createdByEmail || "-"} · ${formatDate(detail.createdAt)}`;

  const role = String(currentUser?.role || "").toLowerCase();

  if (role === "student") {
    professorSubmissionPanel.classList.add("hidden");
    renderStudentScorePanel(detail.mySubmission || null);
    renderStudentAnswerForm(detail);
  } else {
    if (studentScorePanel) studentScorePanel.classList.add("hidden");
    studentAnswerForm.classList.add("hidden");
    professorSubmissionPanel.classList.remove("hidden");
    const submissions = await fetchSubmissions(formId);
    renderProfessorSubmissions(submissions);
  }

  renderFormsList(currentItems);
}

function renderProfessorSubmissions(submissions) {
  const items = submissions?.submissions || [];

  if (!items.length) {
    submissionsList.innerHTML = `<article class="empty-state">No submissions yet.</article>`;
    return;
  }

  submissionsList.innerHTML = items
    .map(
      (submission) => `
        <article class="submission-card" data-submission-id="${submission.submissionId}">
          <h5>${submission.studentEmail || "-"}</h5>
          <p class="muted">Submitted: ${formatDate(submission.submittedAt)}</p>
          <p class="muted">
            Score: ${submission.score ?? "Not graded"}
            ${submission.gradedAt ? `· Graded: ${formatDate(submission.gradedAt)}` : ""}
          </p>

          <div class="submission-answers">
            ${(submission.answers || [])
              .map(
                (answer, index) => `
                  <div class="submission-answer-item">
                    <strong>${index + 1}. ${answer.question || "-"}</strong>
                    <p>${answer.answer || "-"}</p>
                  </div>
                `
              )
              .join("")}
          </div>

          <div class="grading-box">
            <label>
              Score
              <input class="grade-score-input" type="number" step="0.01" min="0" value="${submission.score ?? ""}" />
            </label>

            <label>
              Feedback
              <textarea class="grade-feedback-input" rows="3" placeholder="Add feedback...">${submission.feedback || ""}</textarea>
            </label>

            <button class="primary-btn save-grade-btn" type="button">Save Grade</button>
          </div>
        </article>
      `
    )
    .join("");
}

function showEmptyDetail() {
  selectedItem = null;
  detailCard.classList.add("hidden");
  emptyDetail.classList.remove("hidden");
  studentAnswerForm.classList.add("hidden");
  professorSubmissionPanel.classList.add("hidden");
  if (studentScorePanel) studentScorePanel.classList.add("hidden");
  submissionsList.innerHTML = "";
}
async function openForm(formId) {
  const detail = await fetchFormDetail(formId);
  selectedItem = detail;

  emptyDetail.classList.add("hidden");
  detailCard.classList.remove("hidden");

  detailFormTitle.textContent = detail.title || "-";
  detailDescription.textContent = detail.description || "-";
  detailCreatedMeta.textContent = `By ${detail.createdByEmail || "-"} · ${formatDate(detail.createdAt)}`;

  const role = String(currentUser?.role || "").toLowerCase();

  if (role === "student") {
    professorSubmissionPanel.classList.add("hidden");
    renderStudentScorePanel(detail.mySubmission || null);
    renderStudentAnswerForm(detail);
  } else {
    if (studentScorePanel) studentScorePanel.classList.add("hidden");
    studentAnswerForm.classList.add("hidden");
    professorSubmissionPanel.classList.remove("hidden");
    const submissions = await fetchSubmissions(formId);
    renderProfessorSubmissions(submissions);
  }

  renderFormsList(currentItems);
}

async function loadForms() {
  showEmptyDetail();
  setPageMessage("");

  const data = await fetchForms(currentKind);
  renderFormsList(data.forms || []);
}

typeTabs.forEach((tab) => {
  tab.addEventListener("click", async () => {
    setActiveTab(tab.dataset.kind);
    await loadForms();
  });
});

if (addShortAnswerBtn) {
  addShortAnswerBtn.addEventListener("click", () => createQuestionBuilderCard("short_answer"));
}
if (addParagraphBtn) {
  addParagraphBtn.addEventListener("click", () => createQuestionBuilderCard("paragraph"));
}
if (addMultipleChoiceBtn) {
  addMultipleChoiceBtn.addEventListener("click", () => createQuestionBuilderCard("multiple_choice"));
}

if (builderForm) {
  builderForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const title = formTitle.value.trim();
    const description = formDescription.value.trim();
    const questions = collectBuilderQuestions();

    if (!title || !description) {
      setPageMessage("Title and description are required.", true);
      return;
    }

    if (!questions.length) {
      setPageMessage("Add at least one question.", true);
      return;
    }

    if (questions.some((q) => !q.question)) {
      setPageMessage("Each question must have text.", true);
      return;
    }

    if (questions.some((q) => q.type === "multiple_choice" && (!q.choices || q.choices.length < 2))) {
      setPageMessage("Multiple choice questions need at least 2 choices.", true);
      return;
    }

    saveFormBtn.disabled = true;
    saveFormBtn.textContent = "Publishing...";
    setPageMessage("");

    try {
      const payload = {
        kind: currentKind,
        title,
        description,
        questions
      };

      const result = await createForm(payload);
      setPageMessage(result.message || `${prettyKind(currentKind)} created.`);
      resetBuilder();
      await loadForms();
    } catch (error) {
      setPageMessage(error.message || "Failed to publish form.", true);
    } finally {
      saveFormBtn.disabled = false;
      saveFormBtn.textContent = "Publish Form";
    }
  });
}

if (formsList) {
  formsList.addEventListener("click", async (event) => {
    const item = event.target.closest(".form-list-item");
    if (!item) return;

    const formId = item.dataset.formId;
    if (!formId) return;

    if (event.target.closest(".open-form-btn")) {
      try {
        await openForm(formId);
      } catch (error) {
        setPageMessage(error.message || "Failed to open form.", true);
      }
      return;
    }

    if (event.target.closest(".delete-form-btn")) {
      const confirmed = window.confirm("Delete this form?");
      if (!confirmed) return;

      try {
        const result = await deleteForm(formId);
        setPageMessage(result.message || "Form deleted.");
        await loadForms();
      } catch (error) {
        setPageMessage(error.message || "Failed to delete form.", true);
      }
    }
  });
}

if (submissionsList) {
  submissionsList.addEventListener("click", async (event) => {
    const saveBtn = event.target.closest(".save-grade-btn");
    if (!saveBtn) return;

    const card = event.target.closest(".submission-card");
    if (!card) return;

    const submissionId = card.dataset.submissionId;
    const scoreInput = card.querySelector(".grade-score-input");
    const feedbackInput = card.querySelector(".grade-feedback-input");

    if (!submissionId || !scoreInput) return;

    const scoreValue = scoreInput.value.trim();

    if (scoreValue === "") {
      setPageMessage("Score is required.", true);
      return;
    }

    saveBtn.disabled = true;
    saveBtn.textContent = "Saving...";

    try {
      const result = await gradeSubmission(submissionId, {
        score: Number(scoreValue),
        feedback: String(feedbackInput?.value || "").trim()
      });

      setPageMessage(result.message || "Grade saved.");

      if (selectedItem?.id) {
        await openForm(selectedItem.id);
      }

    } catch (error) {
      setPageMessage(error.message || "Failed to save grade.", true);
    } finally {
      saveBtn.disabled = false;
      saveBtn.textContent = "Save Grade";
    }
  });
}

if (studentAnswerForm) {
  studentAnswerForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    if (!selectedItem?.id) return;

    const answers = [];

    const questionIds = [...studentAnswerForm.querySelectorAll("[data-question-id]")]
      .map((el) => el.dataset.questionId)
      .filter((value, index, array) => array.indexOf(value) === index);

    questionIds.forEach((questionId) => {
      const radioInputs = studentAnswerForm.querySelectorAll(`input[type="radio"][data-question-id="${questionId}"]`);
      if (radioInputs.length) {
        const checked = [...radioInputs].find((input) => input.checked);
        answers.push({
          questionId: Number(questionId),
          answer: checked ? checked.value : ""
        });
        return;
      }

      const input = studentAnswerForm.querySelector(`[data-question-id="${questionId}"]`);
      answers.push({
        questionId: Number(questionId),
        answer: input ? String(input.value || "").trim() : ""
      });
    });

    const submitBtn = document.getElementById("submitStudentAnswersBtn");
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.textContent = "Submitting...";
    }

    try {
      const result = await submitFormAnswers(selectedItem.id, { answers });
      setPageMessage(result.message || "Answers submitted.");
      await openForm(selectedItem.id);
    } catch (error) {
      setPageMessage(error.message || "Failed to submit answers.", true);
    } finally {
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.textContent = "Submit Answers";
      }
    }
  });
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

(async function initMaterialPage() {
  applyTheme(getPreferredTheme());

  currentUser = await getCurrentUser();
  if (!currentUser) {
    window.location.href = "index.html";
    return;
  }

  const role = String(currentUser.role || "").toLowerCase();
  if (!["student", "professor"].includes(role)) {
    setPageMessage("This page is only available for professors and students.", true);
    professorBuilderCard.classList.add("hidden");
    formsList.innerHTML = `<article class="empty-state">Access denied.</article>`;
    return;
  }

  updateRoleUi();
  resetBuilder();
  await loadForms();
})();