document.getElementById('login-form').addEventListener('submit', async event => {
  event.preventDefault();
  const button = document.getElementById('login-button'), error = document.getElementById('login-error');
  button.disabled = true; error.hidden = true;
  try {
    const response = await fetch('/api/auth/login', {method: 'POST', headers: {'Content-Type': 'application/json', 'X-SAST-Client': 'dashboard'},
      body: JSON.stringify({username: document.getElementById('username').value, password: document.getElementById('password').value})});
    if (!response.ok) throw new Error(response.status === 429 ? 'Muitas tentativas. Aguarde um minuto antes de tentar novamente.' : 'Não foi possível entrar. Confira seu usuário e senha.');
    document.getElementById('password').value = '';
    location.replace('/');
  } catch (reason) { error.textContent = reason.message; error.hidden = false; button.disabled = false; }
});
