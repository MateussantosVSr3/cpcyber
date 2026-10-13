import http from 'node:http';
import { spawn } from 'node:child_process';
import { mkdir } from 'node:fs/promises';
import { timingSafeEqual } from 'node:crypto';
import { RpcClient, reviewFinding } from './rpc.mjs';

const token = process.env.BRIDGE_TOKEN;
if (!token || token.length < 32) throw new Error('BRIDGE_TOKEN must contain at least 32 characters');
const cwd = process.env.REVIEW_DIR || '/tmp/sast-review';
await mkdir(cwd, { recursive: true });
const child = spawn(process.env.CODEX_BIN || 'codex', ['app-server'], {
  cwd, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true
});
const rpc = new RpcClient(child);
let ready = false, busy = false, loginPending = false;
let lastLogin = null;
let shuttingDown = false;
rpc.on('notification', message => {
  if (message.method === 'account/login/completed') {
    loginPending = false;
    lastLogin = { success: Boolean(message.params.success), error: message.params.success ? null : 'Login não concluído. Tente novamente.' };
  }
});
rpc.on('disconnected', () => {
  ready = false;
  if (!shuttingDown) {
    console.error('Codex App Server disconnected; restarting bridge container.');
    setTimeout(() => process.exit(1), 10);
  }
});
rpc.initialize().then(() => { ready = true; }).catch(() => {
  ready = false;
  console.error('Codex App Server initialization failed; restarting bridge container.');
  child.kill();
  setTimeout(() => process.exit(1), 10);
});
function authorized(req) {
  const provided = Buffer.from(req.headers.authorization || '');
  const expected = Buffer.from('Bearer ' + token);
  return provided.length === expected.length && timingSafeEqual(provided, expected);
}
function send(res, status, body) { res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(body)); }
async function body(req) {
  let data = '';
  for await (const chunk of req) { data += chunk; if (data.length > 60000) throw new Error('Payload too large'); }
  return JSON.parse(data || '{}');
}
const server = http.createServer(async (req, res) => {
  if (!authorized(req)) return send(res, 401, { error: 'Unauthorized' });
  if (!ready) return send(res, 503, { error: 'Codex App Server unavailable' });
  try {
    if (req.method === 'GET' && req.url === '/account') {
      const result = await rpc.call('account/read', { refreshToken: false });
      return send(res, 200, { connected: Boolean(result.account), account: result.account ? { type: result.account.type, planType: result.account.planType } : null, loginPending, lastLogin });
    }
    if (req.method !== 'POST') return send(res, 404, { error: 'Not found' });
    if (req.url === '/login') {
      if (busy || loginPending) return send(res, 409, { error: 'Aguarde a operação atual.' });
      loginPending = true; lastLogin = null;
      try {
        const result = await rpc.call('account/login/start', { type: 'chatgptDeviceCode' });
        const url = new URL(result.verificationUrl);
        if (url.protocol !== 'https:' || url.hostname !== 'auth.openai.com') throw new Error('Unexpected login URL');
        return send(res, 200, { verificationUrl: url.href, userCode: result.userCode });
      } catch (error) { loginPending = false; throw error; }
    }
    if (req.url === '/logout') {
      if (busy) return send(res, 409, { error: 'Aguarde a revisão atual.' });
      await rpc.call('account/logout'); loginPending = false; lastLogin = null;
      return send(res, 200, { connected: false });
    }
    if (req.url === '/review') {
      if (busy || loginPending) return send(res, 409, { error: 'Aguarde a operação atual.' });
      const payload = await body(req);
      if (!payload.finding || typeof payload.finding.rule !== 'string') return send(res, 400, { error: 'Invalid finding' });
      busy = true;
      try {
        const account = await rpc.call('account/read', { refreshToken: false });
        if (!account.account) return send(res, 401, { error: 'Conecte sua conta Codex.' });
        return send(res, 200, await reviewFinding(rpc, payload.finding, cwd));
      } finally { busy = false; }
    }
    send(res, 404, { error: 'Not found' });
  } catch (error) {
    console.error(error instanceof Error ? error.message : 'Codex operation failed');
    send(res, 502, { error: 'Codex não concluiu a operação. Verifique login, disponibilidade e limites da conta.' });
  }
});
server.requestTimeout = 210000;
server.listen(Number(process.env.PORT || 8090), process.env.HOST || '127.0.0.1');
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => {
  shuttingDown = true;
  child.kill();
  server.close(() => process.exit(0));
});
