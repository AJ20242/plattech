(async function roleUiGuard() {

  async function getCurrentUser() {
    try {
      const response = await fetch('/api/auth/me', { credentials: 'same-origin' });
      if (!response.ok) return null;
      return response.json();
    } catch {
      return null;
    }
  }

  const user = await getCurrentUser();
  const role = String(user?.role || '').toLowerCase();

  const canUseMaterial = role === 'professor' || role === 'student';

  if (!canUseMaterial) {
    document.querySelectorAll('.material-link').forEach((el) => {
      el.style.display = 'none';
    });
  }

})();