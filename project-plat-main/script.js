const signInCard = document.querySelector('[data-form="signin"]');
const signUpCard = document.querySelector('[data-form="signup"]');
const showSignInBtn = document.getElementById('showSignIn');
const showSignUpBtn = document.getElementById('showSignUp');
const switchBtns = document.querySelectorAll('.switch');
const tabSignIn = document.getElementById('tabSignIn');
const tabSignUp = document.getElementById('tabSignUp');
const signInForm = document.getElementById('signInForm');
const signUpForm = document.getElementById('signUpForm');
const signInEmail = document.getElementById('signInEmail');
const signInPassword = document.getElementById('signInPassword');
const signUpName = document.getElementById('signUpName');
const signUpRole = document.getElementById('signUpRole');
const adminCodeWrap = document.getElementById('adminCodeWrap');
const adminCode = document.getElementById('adminCode');
const signUpEmail = document.getElementById('signUpEmail');
const signUpPassword = document.getElementById('signUpPassword');
const confirmPassword = document.getElementById('confirmPassword');
const signInMessage = document.getElementById('signInMessage');
const signUpMessage = document.getElementById('signUpMessage');
const passwordStrength = document.getElementById('passwordStrength');
const togglePasswordBtns = document.querySelectorAll('.toggle-password');
const formCarousel = document.getElementById('formCarousel');
const themeToggle = document.getElementById('themeToggle');

const mfaCard = document.getElementById('mfaCard');
const mfaForm = document.getElementById('mfaForm');
const mfaCode = document.getElementById('mfaCode');
const verifyMfaBtn = document.getElementById('verifyMfaBtn');
const cancelMfaBtn = document.getElementById('cancelMfaBtn');
const mfaMessage = document.getElementById('mfaMessage');
const mfaDescription = document.getElementById('mfaDescription');

let activeForm = 'signin';
let pendingMfaEmail = '';
const SWITCH_DURATION_MS = 440;
let heightRafId = null;
const THEME_KEY = 'vss-theme';

function switchForm(target) {
  if (!signInCard || !signUpCard || target === activeForm) return;

  hideMfaCard();

  const incoming = target === 'signin' ? signInCard : signUpCard;
  const outgoing = activeForm === 'signin' ? signInCard : signUpCard;
  const movingForward = activeForm === 'signin' && target === 'signup';

  outgoing.classList.remove('is-active');
  outgoing.classList.remove('slide-left', 'slide-right', 'pre-left');
  outgoing.classList.add(movingForward ? 'slide-left' : 'slide-right');

  incoming.classList.remove('slide-left', 'slide-right', 'pre-left');
  if (!movingForward) incoming.classList.add('pre-left');

  requestAnimationFrame(() => {
    incoming.classList.remove('pre-left');
    incoming.classList.add('is-active');
    scheduleHeightSync();
  });

  setTimeout(() => {
    outgoing.classList.remove('slide-left', 'slide-right');
    scheduleHeightSync();
  }, SWITCH_DURATION_MS);

  activeForm = target;
  updateTabState();
  scheduleHeightSync();
}

function updateTabState() {
  if (!tabSignIn || !tabSignUp || !signInCard || !signUpCard) return;
  const signInActive = activeForm === 'signin';
  tabSignIn.classList.toggle('is-active', signInActive);
  tabSignUp.classList.toggle('is-active', !signInActive);
  tabSignIn.setAttribute('aria-selected', signInActive ? 'true' : 'false');
  tabSignUp.setAttribute('aria-selected', signInActive ? 'false' : 'true');
  signInCard.setAttribute('aria-hidden', signInActive ? 'false' : 'true');
  signUpCard.setAttribute('aria-hidden', signInActive ? 'true' : 'false');
}

function syncCarouselHeight() {
  if (!formCarousel || !signInCard || !signUpCard) return;
  let targetHeight = 0;

  if (!mfaCard?.classList.contains('hidden')) {
    targetHeight = Math.ceil(mfaCard.scrollHeight);
  } else {
    const activeCard = activeForm === 'signin' ? signInCard : signUpCard;
    targetHeight = Math.ceil(activeCard.scrollHeight);
  }

  formCarousel.style.height = `${targetHeight}px`;
}

function scheduleHeightSync() {
  if (heightRafId) cancelAnimationFrame(heightRafId);
  heightRafId = requestAnimationFrame(() => {
    heightRafId = null;
    syncCarouselHeight();
  });
}

function getPreferredTheme() {
  const saved = localStorage.getItem(THEME_KEY);
  if (saved === 'light' || saved === 'dark') return saved;
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function updateThemeLabel(theme) {
  if (!themeToggle) return;
  const dark = theme === 'dark';
  themeToggle.setAttribute('aria-label', dark ? 'Enable light mode' : 'Enable dark mode');
}

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  updateThemeLabel(theme);
}

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

async function apiRequest(path, payload) {
  const response = await fetch(path, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    credentials: 'same-origin',
    body: JSON.stringify(payload)
  });

  const data = await response.json().catch(() => ({
    message: 'Unexpected server response.'
  }));

  if (!response.ok) {
    throw new Error(data.message || data.detail || 'Request failed.');
  }

  return data;
}

function scorePassword(password) {
  let score = 0;
  if (password.length >= 8) score += 1;
  if (/[a-z]/.test(password)) score += 1;
  if (/[A-Z]/.test(password)) score += 1;
  if (/[0-9]/.test(password)) score += 1;
  if (/[^A-Za-z0-9]/.test(password)) score += 1;
  return score;
}

function isStrongPassword(password) {
  return scorePassword(password) === 5;
}

function updateStrengthLabel(password) {
  if (!passwordStrength) return;

  const score = scorePassword(password);
  let label = 'Strength: -';
  let className = 'password-strength neutral';

  if (password.length > 0 && score <= 2) {
    label = 'Strength: Weak';
    className = 'password-strength weak';
  } else if (score === 3 || score === 4) {
    label = 'Strength: Medium';
    className = 'password-strength medium';
  } else if (score === 5) {
    label = 'Strength: Strong';
    className = 'password-strength strong';
  }

  passwordStrength.textContent = label;
  passwordStrength.className = className;
  scheduleHeightSync();
}

function showMessage(el, text, type = '') {
  if (!el) return;
  el.textContent = text;
  el.className = `form-message${type ? ` ${type}` : ''}`;
  scheduleHeightSync();
}

function clearMessage(el) {
  if (!el) return;
  el.textContent = '';
  el.className = 'form-message';
  scheduleHeightSync();
}

function toggleInvalid(input, invalid) {
  if (!input) return;
  input.classList.toggle('is-invalid', invalid);
}

function setLoadingState(form, loading) {
  if (!form) return;
  const submitBtn = form.querySelector('button[type="submit"]');
  if (!submitBtn) return;

  if (!submitBtn.dataset.defaultLabel) {
    submitBtn.dataset.defaultLabel = submitBtn.textContent;
  }

  submitBtn.disabled = loading;
  submitBtn.textContent = loading ? 'Please wait...' : submitBtn.dataset.defaultLabel;
  scheduleHeightSync();
}

function showMfaCard(email) {
  pendingMfaEmail = email || '';

  if (mfaCard) {
    mfaCard.classList.remove('hidden');
    mfaCard.setAttribute('aria-hidden', 'false');
  }

  if (signInCard) {
    signInCard.classList.remove('is-active');
    signInCard.setAttribute('aria-hidden', 'true');
  }

  if (signUpCard) {
    signUpCard.setAttribute('aria-hidden', 'true');
  }

  if (mfaDescription) {
    mfaDescription.textContent = `We sent a 6-digit verification code to ${email}.`;
  }

  if (mfaCode) {
    mfaCode.value = '';
    mfaCode.focus();
  }

  setMfaMessage('');
  scheduleHeightSync();
}

function hideMfaCard() {
  pendingMfaEmail = '';

  if (mfaCard) {
    mfaCard.classList.add('hidden');
    mfaCard.setAttribute('aria-hidden', 'true');
  }

  if (signInCard) {
    signInCard.classList.add('is-active');
    signInCard.setAttribute('aria-hidden', 'false');
  }

  setMfaMessage('');
  scheduleHeightSync();
}

function setMfaMessage(text, type = '') {
  if (!mfaMessage) return;
  mfaMessage.textContent = text;
  mfaMessage.classList.remove('error', 'success');
  if (type) mfaMessage.classList.add(type);
  scheduleHeightSync();
}

if (showSignInBtn) showSignInBtn.addEventListener('click', () => switchForm('signin'));
if (showSignUpBtn) showSignUpBtn.addEventListener('click', () => switchForm('signup'));

if (tabSignIn && tabSignUp) {
  tabSignIn.addEventListener('click', () => switchForm('signin'));
  tabSignUp.addEventListener('click', () => switchForm('signup'));
  tabSignIn.addEventListener('keydown', (event) => {
    if (event.key === 'ArrowRight') switchForm('signup');
  });
  tabSignUp.addEventListener('keydown', (event) => {
    if (event.key === 'ArrowLeft') switchForm('signin');
  });
}

switchBtns.forEach((btn) => {
  btn.addEventListener('click', () => {
    switchForm(btn.dataset.target);
  });
});

if (themeToggle) {
  themeToggle.addEventListener('click', () => {
    const current = document.documentElement.getAttribute('data-theme') || 'light';
    const next = current === 'dark' ? 'light' : 'dark';
    applyTheme(next);
    localStorage.setItem(THEME_KEY, next);
  });
}

if (signUpRole) {
  signUpRole.addEventListener('change', () => {
    const isAdmin = signUpRole.value === 'administrator';
    if (adminCodeWrap) adminCodeWrap.classList.toggle('hidden', !isAdmin);
    if (adminCode) {
      adminCode.required = isAdmin;
      if (!isAdmin) adminCode.value = '';
    }
    scheduleHeightSync();
  });
}

if (signInForm && signUpForm) {
  [...signInForm.querySelectorAll('input'), ...signUpForm.querySelectorAll('input')].forEach((input) => {
    input.addEventListener('input', () => {
      input.classList.remove('is-invalid');
      if (signInForm.contains(input)) clearMessage(signInMessage);
      if (signUpForm.contains(input)) clearMessage(signUpMessage);
    });
  });
}

togglePasswordBtns.forEach((btn) => {
  btn.addEventListener('click', () => {
    const targetInput = document.getElementById(btn.dataset.toggleFor);
    if (!targetInput) return;
    const show = targetInput.type === 'password';
    targetInput.type = show ? 'text' : 'password';
    btn.textContent = show ? 'Hide' : 'Show';
    btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
  });
});

if (signUpPassword) {
  signUpPassword.addEventListener('input', () => {
    updateStrengthLabel(signUpPassword.value);

    if (confirmPassword && confirmPassword.value.length > 0) {
      const mismatch = signUpPassword.value !== confirmPassword.value;
      toggleInvalid(confirmPassword, mismatch);
    }
  });
}

if (confirmPassword) {
  confirmPassword.addEventListener('input', () => {
    const mismatch = signUpPassword.value !== confirmPassword.value;
    toggleInvalid(confirmPassword, mismatch);
  });
}

if (signInForm) {
  signInForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    setLoadingState(signInForm, true);

    const email = normalizeEmail(signInEmail?.value);
    const password = signInPassword?.value || '';
    const validEmail = signInEmail?.checkValidity?.() ?? false;
    const weak = password.length < 8;

    toggleInvalid(signInEmail, !validEmail);
    toggleInvalid(signInPassword, weak);

    if (!email || !password) {
      showMessage(signInMessage, 'Please enter both email and password.', 'error');
      setLoadingState(signInForm, false);
      return;
    }

    if (!validEmail) {
      showMessage(signInMessage, 'Enter a valid email address.', 'error');
      setLoadingState(signInForm, false);
      return;
    }

    if (weak) {
      showMessage(signInMessage, 'Password must be at least 8 characters.', 'error');
      setLoadingState(signInForm, false);
      return;
    }

    try {
      const result = await apiRequest('/api/auth/signin', { email, password });

      if (result?.mfaRequired) {
        showMessage(signInMessage, '', '');
        showMfaCard(email);
        setLoadingState(signInForm, false);
        return;
      }

      showMessage(signInMessage, 'Sign in successful. Redirecting...', 'success');
      setLoadingState(signInForm, false);

      setTimeout(() => {
        window.location.href = 'dashboard.html';
      }, 450);
    } catch (error) {
      showMessage(signInMessage, error.message || 'Invalid email or password.', 'error');
      setLoadingState(signInForm, false);
    }
  });
}

if (signUpForm) {
  signUpForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    setLoadingState(signUpForm, true);

    const fullName = signUpName?.value.trim() || '';
    const role = signUpRole?.value || 'student';
    const adminAccessCode = adminCode?.value.trim() || '';
    const email = normalizeEmail(signUpEmail?.value);
    const password = signUpPassword?.value || '';
    const confirm = confirmPassword?.value || '';

    const validName = fullName.length >= 2;
    const validRole = ['student', 'professor', 'administrator'].includes(role);
    const validEmail = signUpEmail?.checkValidity?.() ?? false;
    const strong = isStrongPassword(password);
    const matched = password === confirm;

    toggleInvalid(signUpName, !validName);
    toggleInvalid(signUpRole, !validRole);
    toggleInvalid(signUpEmail, !validEmail);
    toggleInvalid(signUpPassword, !strong);
    toggleInvalid(confirmPassword, !matched);

    if (!fullName || !email || !password || !confirm || !role) {
      showMessage(signUpMessage, 'Please complete all required fields.', 'error');
      setLoadingState(signUpForm, false);
      return;
    }

    if (!validRole) {
      showMessage(signUpMessage, 'Please choose a valid role.', 'error');
      setLoadingState(signUpForm, false);
      return;
    }

    if (role === 'administrator' && !adminAccessCode) {
      showMessage(signUpMessage, 'Admin access code is required for administrator role.', 'error');
      setLoadingState(signUpForm, false);
      return;
    }

    if (!validName) {
      showMessage(signUpMessage, 'Full name must be at least 2 characters.', 'error');
      setLoadingState(signUpForm, false);
      return;
    }

    if (!validEmail) {
      showMessage(signUpMessage, 'Enter a valid email address.', 'error');
      setLoadingState(signUpForm, false);
      return;
    }

    if (!strong) {
      showMessage(signUpMessage, 'Use 8+ chars with upper/lowercase, number, and symbol.', 'error');
      setLoadingState(signUpForm, false);
      return;
    }

    if (!matched) {
      showMessage(signUpMessage, 'Passwords do not match.', 'error');
      setLoadingState(signUpForm, false);
      return;
    }

    try {
      const result = await apiRequest('/api/auth/signup', {
        fullName,
        role,
        adminCode: adminAccessCode,
        email,
        password
      });

      showMessage(signUpMessage, result.message || 'Account created successfully.', 'success');
      signUpForm.reset();
      updateStrengthLabel('');
      setLoadingState(signUpForm, false);

      setTimeout(() => {
        switchForm('signin');
        if (signInEmail) signInEmail.value = email;
      }, 500);
    } catch (error) {
      showMessage(signUpMessage, error.message || 'Failed to create account.', 'error');
      setLoadingState(signUpForm, false);
    }
  });
}

if (mfaForm) {
  mfaForm.addEventListener('submit', async (event) => {
    event.preventDefault();

    const code = String(mfaCode?.value || '').trim();

    if (!/^\d{6}$/.test(code)) {
      setMfaMessage('Enter a valid 6-digit code.', 'error');
      return;
    }

    if (verifyMfaBtn) verifyMfaBtn.disabled = true;
    setMfaMessage('Verifying code...');

    try {
      await apiRequest('/api/auth/signin/verify-mfa', { code });

      setMfaMessage('Verification successful.', 'success');

      setTimeout(() => {
        window.location.href = 'dashboard.html';
      }, 400);
    } catch (error) {
      setMfaMessage(error.message || 'Invalid code.', 'error');
    } finally {
      if (verifyMfaBtn) verifyMfaBtn.disabled = false;
    }
  });
}

if (cancelMfaBtn) {
  cancelMfaBtn.addEventListener('click', () => {
    hideMfaCard();
    showMessage(signInMessage, 'MFA cancelled. Please sign in again.');
  });
}

if (mfaCode) {
  mfaCode.addEventListener('input', (event) => {
    event.target.value = event.target.value.replace(/\D/g, '').slice(0, 6);
  });
}

updateTabState();
applyTheme(getPreferredTheme());

if (signUpRole) {
  signUpRole.dispatchEvent(new Event('change'));
}

if (formCarousel) {
  syncCarouselHeight();
  window.addEventListener('resize', scheduleHeightSync);
  window.addEventListener('load', scheduleHeightSync);

  if (document.fonts && document.fonts.ready) {
    document.fonts.ready.then(scheduleHeightSync);
  }

  if (typeof ResizeObserver !== 'undefined' && signInCard && signUpCard) {
    const observer = new ResizeObserver(() => scheduleHeightSync());
    observer.observe(signInCard);
    observer.observe(signUpCard);
    if (mfaCard) observer.observe(mfaCard);
  }
}