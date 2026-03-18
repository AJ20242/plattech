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

let resendMfaBtn = document.getElementById('resendMfaBtn');

let activeForm = 'signin';
let pendingMfaEmail = '';
let isSigningIn = false;
let isSigningUp = false;
let isVerifyingMfa = false;
let isResendingMfa = false;
let resendCooldown = 0;
let resendInterval = null;

const SWITCH_DURATION_MS = 440;
let heightRafId = null;
const THEME_KEY = 'vss-theme';

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function updateTabState() {
  if (!tabSignIn || !tabSignUp) return;
  const signInActive = activeForm === 'signin';
  tabSignIn.classList.toggle('is-active', signInActive);
  tabSignUp.classList.toggle('is-active', !signInActive);
  tabSignIn.setAttribute('aria-selected', signInActive ? 'true' : 'false');
  tabSignUp.setAttribute('aria-selected', signInActive ? 'false' : 'true');
}

function syncCarouselHeight() {
  if (!formCarousel || !signInCard || !signUpCard) return;

  let targetHeight = 0;
  if (mfaCard && !mfaCard.classList.contains('hidden')) {
    targetHeight = Math.ceil(signInCard.scrollHeight);
  } else {
    const activeCard = activeForm === 'signin' ? signInCard : signUpCard;
    targetHeight = Math.ceil(activeCard.scrollHeight);
  }

  formCarousel.style.height = `${Math.max(targetHeight, 560)}px`;
}

function scheduleHeightSync() {
  if (heightRafId) cancelAnimationFrame(heightRafId);
  heightRafId = requestAnimationFrame(() => {
    heightRafId = null;
    syncCarouselHeight();
  });
}

function switchForm(target) {
  if (!signInCard || !signUpCard || target === activeForm) return;

  hideMfaCard();

  const incoming = target === 'signin' ? signInCard : signUpCard;
  const outgoing = activeForm === 'signin' ? signInCard : signUpCard;
  const movingForward = activeForm === 'signin' && target === 'signup';

  outgoing.classList.remove('is-active', 'slide-left', 'slide-right', 'pre-left');
  outgoing.classList.add(movingForward ? 'slide-left' : 'slide-right');
  outgoing.setAttribute('aria-hidden', 'true');

  incoming.classList.remove('is-active', 'slide-left', 'slide-right', 'pre-left');
  if (!movingForward) {
    incoming.classList.add('pre-left');
  } else {
    incoming.style.transform = 'translateX(72px) scale(0.975)';
    incoming.style.opacity = '0';
    incoming.style.filter = 'blur(8px)';
  }

  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      incoming.classList.remove('pre-left');
      incoming.style.transform = '';
      incoming.style.opacity = '';
      incoming.style.filter = '';
      incoming.classList.add('is-active');
      incoming.setAttribute('aria-hidden', 'false');
      scheduleHeightSync();
    });
  });

  setTimeout(() => {
    outgoing.classList.remove('slide-left', 'slide-right');
    scheduleHeightSync();
  }, SWITCH_DURATION_MS);

  activeForm = target;
  updateTabState();
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

function setMfaMessage(text, type = '') {
  if (!mfaMessage) return;
  mfaMessage.textContent = text;
  mfaMessage.className = `form-message${type ? ` ${type}` : ''}`;
  scheduleHeightSync();
}

function toggleInvalid(input, invalid) {
  if (!input) return;
  input.classList.toggle('is-invalid', invalid);
}

function setButtonLoading(button, loading, loadingText = 'Please wait...') {
  if (!button) return;
  if (!button.dataset.defaultLabel) {
    button.dataset.defaultLabel = button.textContent;
  }
  button.disabled = loading;
  button.textContent = loading ? loadingText : button.dataset.defaultLabel;
}

function ensureResendButton() {
  if (resendMfaBtn || !mfaForm) return;

  resendMfaBtn = document.createElement('button');
  resendMfaBtn.type = 'button';
  resendMfaBtn.id = 'resendMfaBtn';
  resendMfaBtn.className = 'secondary-btn';
  resendMfaBtn.textContent = 'Send code again';

  const actions = mfaForm.querySelector('.mfa-actions');
  if (actions) {
    actions.appendChild(resendMfaBtn);
  } else {
    mfaForm.appendChild(resendMfaBtn);
  }

  resendMfaBtn.addEventListener('click', handleResendMfa);
  scheduleHeightSync();
}

function updateResendButtonLabel() {
  if (!resendMfaBtn) return;

  if (isResendingMfa) {
    resendMfaBtn.disabled = true;
    resendMfaBtn.textContent = 'Sending...';
    return;
  }

  if (resendCooldown > 0) {
    resendMfaBtn.disabled = true;
    resendMfaBtn.textContent = `Send again in ${resendCooldown}s`;
    return;
  }

  resendMfaBtn.disabled = false;
  resendMfaBtn.textContent = 'Send code again';
}

function startResendCooldown(seconds = 30) {
  resendCooldown = seconds;
  updateResendButtonLabel();

  if (resendInterval) clearInterval(resendInterval);

  resendInterval = setInterval(() => {
    resendCooldown -= 1;
    if (resendCooldown <= 0) {
      resendCooldown = 0;
      clearInterval(resendInterval);
      resendInterval = null;
    }
    updateResendButtonLabel();
  }, 1000);
}

function showMfaCard(email) {
  pendingMfaEmail = email || '';
  activeForm = 'signin';

  if (signUpCard) {
    signUpCard.classList.remove('is-active', 'slide-left', 'slide-right', 'pre-left');
    signUpCard.setAttribute('aria-hidden', 'true');
  }

  if (signInCard) {
    signInCard.classList.add('is-active');
    signInCard.classList.remove('slide-left', 'slide-right', 'pre-left');
    signInCard.setAttribute('aria-hidden', 'false');
  }

  if (mfaCard) {
    mfaCard.classList.remove('hidden');
    mfaCard.setAttribute('aria-hidden', 'false');
  }

  if (mfaDescription) {
    mfaDescription.textContent = email
      ? `We sent a 6-digit verification code to ${email}.`
      : 'We sent a 6-digit verification code to your email.';
  }

  if (mfaCode) {
    mfaCode.value = '';
    setTimeout(() => mfaCode.focus(), 0);
  }

  ensureResendButton();
  startResendCooldown(30);
  updateTabState();
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
    signInCard.setAttribute('aria-hidden', activeForm === 'signin' ? 'false' : 'true');
  }

  if (signUpCard) {
    signUpCard.setAttribute('aria-hidden', activeForm === 'signup' ? 'false' : 'true');
  }

  if (resendInterval) {
    clearInterval(resendInterval);
    resendInterval = null;
  }

  resendCooldown = 0;
  updateResendButtonLabel();
  setMfaMessage('');
  scheduleHeightSync();
}

function getPreferredTheme() {
  const saved = localStorage.getItem(THEME_KEY);
  if (saved === 'light' || saved === 'dark') return saved;
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function updateThemeLabel(theme) {
  if (!themeToggle) return;
  themeToggle.setAttribute('aria-label', theme === 'dark' ? 'Enable light mode' : 'Enable dark mode');
}

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  updateThemeLabel(theme);
}

async function apiRequest(path, payload) {
  const response = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
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

function updateStrengthLabel(password) {
  if (!passwordStrength) return;

  const score = scorePassword(password);
  let label = 'Strength: -';
  let className = 'password-strength neutral';

  if (!password) {
    label = 'Strength: -';
  } else if (score <= 2) {
    label = 'Weak password';
    className = 'password-strength weak';
  } else if (score <= 4) {
    label = 'Moderate password';
    className = 'password-strength medium';
  } else {
    label = 'Strong password';
    className = 'password-strength strong';
  }

  passwordStrength.textContent = label;
  passwordStrength.className = className;
  scheduleHeightSync();
}

async function handleResendMfa() {
  if (isResendingMfa || resendCooldown > 0) return;

  isResendingMfa = true;
  updateResendButtonLabel();
  setMfaMessage('');

  try {
    const data = await apiRequest('/api/auth/signin/resend-mfa', {});
    if (data.emailSent) {
      setMfaMessage(data.message || 'A new verification code was sent.', 'success');
    } else if (data.verificationCode) {
      setMfaMessage(`Email is not configured. Use this code: ${data.verificationCode}`, 'success');
    } else {
      setMfaMessage(data.message || 'A new verification code was sent.', 'success');
    }
    startResendCooldown(30);
  } catch (error) {
    setMfaMessage(error.message || 'Failed to resend verification code.', 'error');
  } finally {
    isResendingMfa = false;
    updateResendButtonLabel();
  }
}

if (showSignInBtn) showSignInBtn.addEventListener('click', () => switchForm('signin'));
if (showSignUpBtn) showSignUpBtn.addEventListener('click', () => switchForm('signup'));

if (tabSignIn) tabSignIn.addEventListener('click', () => switchForm('signin'));
if (tabSignUp) tabSignUp.addEventListener('click', () => switchForm('signup'));

switchBtns.forEach((btn) => {
  btn.addEventListener('click', () => switchForm(btn.dataset.target));
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
      toggleInvalid(confirmPassword, signUpPassword.value !== confirmPassword.value);
    }
  });
}

if (confirmPassword) {
  confirmPassword.addEventListener('input', () => {
    toggleInvalid(confirmPassword, signUpPassword.value !== confirmPassword.value);
  });
}

if (signInForm) {
  signInForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (isSigningIn) return;

    isSigningIn = true;
    clearMessage(signInMessage);

    const submitBtn = signInForm.querySelector('button[type="submit"]');
    setButtonLoading(submitBtn, true, 'Signing in...');

    try {
      const email = normalizeEmail(signInEmail?.value);
      const password = signInPassword?.value || '';

      if (!email || !password) {
        showMessage(signInMessage, 'Please enter both email and password.', 'error');
        return;
      }

      const data = await apiRequest('/api/auth/signin', { email, password });

      if (data.mfaRequired) {
        showMfaCard(email);
        if (data.emailSent) {
          setMfaMessage('Enter the 6-digit code sent to your email.', 'success');
        } else if (data.verificationCode) {
          setMfaMessage(`Email is not configured. Use this code: ${data.verificationCode}`, 'success');
        }
      } else {
        showMessage(signInMessage, data.message || 'Sign in successful.', 'success');
        setTimeout(() => {
          window.location.href = 'dashboard.html';
        }, 500);
      }
    } catch (error) {
      showMessage(signInMessage, error.message || 'Sign in failed.', 'error');
    } finally {
      isSigningIn = false;
      setButtonLoading(submitBtn, false);
    }
  });
}

if (signUpForm) {
  signUpForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (isSigningUp) return;

    isSigningUp = true;
    clearMessage(signUpMessage);

    const submitBtn = signUpForm.querySelector('button[type="submit"]');
    setButtonLoading(submitBtn, true, 'Creating...');

    try {
      const fullName = signUpName?.value.trim() || '';
      const role = signUpRole?.value || 'student';
      const adminAccessCode = adminCode?.value.trim() || '';
      const email = normalizeEmail(signUpEmail?.value);
      const password = signUpPassword?.value || '';
      const confirm = confirmPassword?.value || '';

      if (!fullName || !email || !password || !confirm) {
        showMessage(signUpMessage, 'Please complete all required fields.', 'error');
        return;
      }

      if (password !== confirm) {
        toggleInvalid(confirmPassword, true);
        showMessage(signUpMessage, 'Passwords do not match.', 'error');
        return;
      }

      const result = await apiRequest('/api/auth/signup', {
        fullName,
        role,
        adminCode: adminAccessCode || null,
        email,
        password
      });

      showMessage(signUpMessage, result.message || 'Account created successfully.', 'success');

      signUpForm.reset();
      updateStrengthLabel('');
      if (adminCodeWrap) adminCodeWrap.classList.add('hidden');

      setTimeout(() => {
        switchForm('signin');
      }, 700);
    } catch (error) {
      showMessage(signUpMessage, error.message || 'Sign up failed.', 'error');
    } finally {
      isSigningUp = false;
      setButtonLoading(submitBtn, false);
    }
  });
}

if (mfaForm) {
  mfaForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (isVerifyingMfa) return;

    isVerifyingMfa = true;
    setMfaMessage('');
    setButtonLoading(verifyMfaBtn, true, 'Verifying...');

    try {
      const code = String(mfaCode?.value || '').trim();
      const data = await apiRequest('/api/auth/signin/verify-mfa', { code });
      setMfaMessage(data.message || 'Verification successful.', 'success');

      setTimeout(() => {
        window.location.href = 'dashboard.html';
      }, 500);
    } catch (error) {
      setMfaMessage(error.message || 'Verification failed.', 'error');
    } finally {
      isVerifyingMfa = false;
      setButtonLoading(verifyMfaBtn, false);
    }
  });
}

if (cancelMfaBtn) {
  cancelMfaBtn.addEventListener('click', () => hideMfaCard());
}

document.addEventListener('DOMContentLoaded', () => {
  applyTheme(getPreferredTheme());
  updateStrengthLabel(signUpPassword?.value || '');

  if (adminCodeWrap && signUpRole) {
    const isAdmin = signUpRole.value === 'administrator';
    adminCodeWrap.classList.toggle('hidden', !isAdmin);
  }

  if (signInCard) signInCard.setAttribute('aria-hidden', 'false');
  if (signUpCard) signUpCard.setAttribute('aria-hidden', 'true');

  ensureResendButton();
  hideMfaCard();
  updateTabState();
  scheduleHeightSync();
});

window.addEventListener('resize', scheduleHeightSync);