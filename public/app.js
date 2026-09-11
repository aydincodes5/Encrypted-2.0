/* ─── app.js — Login Page Logic ──────────────────────────────────────────── */

function getSavedSession() {
  const saved = localStorage.getItem('ec_session') || sessionStorage.getItem('ec_session');
  if (!saved) return null;
  try {
    const session = JSON.parse(saved);
    return session && session.username && session.token ? saved : null;
  } catch {
    localStorage.removeItem('ec_session');
    sessionStorage.removeItem('ec_session');
    return null;
  }
}

// A remembered session survives browser restarts; a normal session does not.
if (getSavedSession()) {
  window.location.href = 'chat.html';
}

// ── Toggle password visibility ──────────────────────────────────────────────
const togglePwdBtn = document.getElementById('togglePwd');
const pwdInput     = document.getElementById('password');
const eyeShow      = document.getElementById('eyeShow');
const eyeHide      = document.getElementById('eyeHide');

// Do not prefill credentials. Some password managers ignore autocomplete="off",
// but generally respect readonly fields until the person intentionally focuses
// them. Passwords are never stored by this application.
for (const input of [document.getElementById('username'), pwdInput]) {
  input.addEventListener('focus', () => input.removeAttribute('readonly'), { once: true });
}

togglePwdBtn.addEventListener('click', () => {
  if (pwdInput.type === 'password') {
    pwdInput.type = 'text';
    eyeShow.style.display = 'none';
    eyeHide.style.display = '';
  } else {
    pwdInput.type = 'password';
    eyeShow.style.display = '';
    eyeHide.style.display = 'none';
  }
});

// ── Login form submission ───────────────────────────────────────────────────
const loginForm  = document.getElementById('loginForm');
const loginBtn   = document.getElementById('loginBtn');
const btnLabel   = document.getElementById('btnLabel');
const btnArrow   = document.getElementById('btnArrow');
const btnSpinner = document.getElementById('btnSpinner');
const errorDiv   = document.getElementById('loginError');

function showError(msg) {
  errorDiv.textContent = '⚠️  ' + msg;
  errorDiv.style.display = 'flex';
}

function setLoading(loading) {
  loginBtn.disabled = loading;
  btnLabel.textContent = loading ? 'Signing in…' : 'Sign In';
  btnArrow.style.display   = loading ? 'none' : '';
  btnSpinner.style.display = loading ? '' : 'none';
}

loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  errorDiv.style.display = 'none';

  const username = document.getElementById('username').value.trim();
  const password = pwdInput.value;

  if (!username || !password) {
    showError('Please fill in both fields.');
    return;
  }

  setLoading(true);

  try {
    const res  = await fetch('/login', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ username, password })
    });

    const data = await res.json();

    if (!res.ok) {
      showError(data.error || 'Something went wrong. Try again.');
      setLoading(false);
      return;
    }

    // Save session
    const sessionData = JSON.stringify({
      username:    data.username,
      displayName: data.displayName,
      initial:     data.initial,
      token:       data.token
    });
    const remember = document.getElementById('rememberLogin').checked;
    (remember ? localStorage : sessionStorage).setItem('ec_session', sessionData);

    // Redirect to chat
    window.location.href = 'chat.html';

  } catch {
    showError('Cannot reach server. Is it running?');
    setLoading(false);
  }
});

// Allow pressing Enter in the username field to move to password
document.getElementById('username').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    e.preventDefault();
    pwdInput.focus();
  }
});
