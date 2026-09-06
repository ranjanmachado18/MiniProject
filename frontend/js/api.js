// api.js
// VULNERABILITY (CWE-522 Insufficiently Protected Credentials): JWT is
// stored in localStorage (readable by any injected script -> pairs with
// the Stored XSS in transaction notes to enable full token theft).
const API_BASE = 'http://localhost:4000/api';

function saveToken(token) {
  localStorage.setItem('vb_token', token);
}
function getToken() {
  return localStorage.getItem('vb_token');
}
function saveUser(user) {
  localStorage.setItem('vb_user', JSON.stringify(user));
}
function getUser() {
  const u = localStorage.getItem('vb_user');
  return u ? JSON.parse(u) : null;
}
function logout() {
  localStorage.removeItem('vb_token');
  localStorage.removeItem('vb_user');
  window.location.href = 'index.html';
}

async function api(path, opts = {}) {
  const headers = Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {});
  const token = getToken();
  if (token) headers['Authorization'] = 'Bearer ' + token;
  const res = await fetch(API_BASE + path, {
    method: opts.method || 'GET',
    headers,
    credentials: 'include',
    body: opts.body ? JSON.stringify(opts.body) : undefined
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(data.error || 'Request failed'), { data, status: res.status });
  return data;
}

function requireAuth() {
  if (!getToken()) window.location.href = 'index.html';
}
