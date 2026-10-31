const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const vm = require('node:vm');
const { DatabaseSync } = require('node:sqlite');
const { webcrypto } = require('node:crypto');

function loadWorker(fetchImpl = fetch, DateImpl = Date) {
  const source = readFileSync(join(__dirname, '..', 'index.js'), 'utf8')
    .replace('export default {', 'globalThis.worker = {');
  const errors = [];
  const context = vm.createContext({
    Response, Request, URL, TextEncoder, crypto: webcrypto, btoa, Date: DateImpl,
    fetch: fetchImpl, console: { log() {}, error: (...args) => errors.push(args) },
  });
  vm.runInContext(`${source}\nglobalThis.testApi = { handleApi, getDashboard, listMappings, getMalaysiaDate, initDatabase, sendWebhookNotification, sendTelegramNotification, setDatabase: value => { DB = value; } };`, context);
  return { api: context.testApi, worker: context.worker, errors };
}

test('Malaysia date changes at midnight MYT', () => {
  const dateAt = instant => class extends Date { static now() { return Date.parse(instant); } };
  const before = loadWorker(fetch, dateAt('2026-01-01T15:59:59Z')).api;
  const after = loadWorker(fetch, dateAt('2026-01-01T16:00:00Z')).api;
  assert.equal(before.getMalaysiaDate(), '2026-01-01');
  assert.equal(after.getMalaysiaDate(), '2026-01-02');
  assert.equal(after.getMalaysiaDate(-1), '2026-01-01');
});

function memoryDatabase() {
  const db = new DatabaseSync(':memory:');
  return {
    close: () => db.close(),
    prepare(sql) {
      let params = [];
      return {
        bind(...values) { params = values; return this; },
        async run() { const result = db.prepare(sql).run(...params); return { meta: { changes: result.changes } }; },
        async first() { return db.prepare(sql).get(...params); },
        async all() { return { results: db.prepare(sql).all(...params) }; },
      };
    },
  };
}

test('dashboard and list agree on mutually exclusive statuses', async () => {
  const { api } = loadWorker();
  const db = memoryDatabase();
  try {
    api.setDatabase(db);
    await api.initDatabase(db);
    const insert = db.prepare('INSERT INTO mappings (path, target, enabled, expiry) VALUES (?, ?, ?, ?)');
    for (const [path, enabled, expiry] of [
      ['active', 1, null], ['future', 1, api.getMalaysiaDate(4)],
      ['today', 1, api.getMalaysiaDate()], ['boundary', 1, api.getMalaysiaDate(3)],
      ['expired', 1, api.getMalaysiaDate(-1)], ['disabled', 0, api.getMalaysiaDate(-1)],
    ]) await insert.bind(path, 'https://example.com', enabled, expiry).run();
    const dashboard = await api.getDashboard();
    assert.equal(dashboard.total, 6);
    for (const [status, expected] of [['active', 2], ['expiring', 2], ['expired', 1], ['disabled', 1]]) {
      const list = await api.listMappings({ page: 1, pageSize: 10, status, type: 'all', query: '', sortBy: 'path', sortOrder: 'asc' });
      assert.equal(dashboard[status], expected, status);
      assert.equal(list.pagination.totalItems, expected, status);
      assert.ok(list.items.every(item => item.status === status), status);
    }
  } finally { db.close(); }
});

test('login rejects a missing password and issues an expiring session for a valid password', async () => {
  const { api } = loadWorker();
  const login = (password, env) => api.handleApi(new Request('https://example.com/api/login', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password }),
  }), env, {}, new URL('https://example.com/api/login'), 'api/login');
  assert.equal((await login('', {})).status, 500);
  assert.equal((await login('wrong', { PASSWORD: 'secret' })).status, 401);
  const response = await login('secret', { PASSWORD: 'secret' });
  assert.equal(response.status, 200);
  assert.match(response.headers.get('set-cookie'), /HttpOnly; Secure; SameSite=Strict; Max-Age=86400/);
  const cookie = response.headers.get('set-cookie').split(';')[0];
  const session = await api.handleApi(new Request('https://example.com/api/session', { headers: { Cookie: cookie } }), { PASSWORD: 'secret' }, {}, new URL('https://example.com/api/session'), 'api/session');
  assert.equal(session.status, 200);
  const expired = await api.handleApi(new Request('https://example.com/api/session', { headers: { Cookie: 'token=1.invalid' } }), { PASSWORD: 'secret' }, {}, new URL('https://example.com/api/session'), 'api/session');
  assert.equal(expired.status, 401);
});

test('admin routes authenticate before serving the page without accessing D1', async () => {
  const { api, worker } = loadWorker();
  const assetPaths = [];
  const env = { PASSWORD: 'secret', ASSETS: { fetch: async request => {
    assetPaths.push(new URL(request.url).pathname);
    return new Response('admin page');
  } } };
  for (const path of ['/admin', '/admin/', '/admin.html']) {
    const response = await worker.fetch(new Request(`https://example.com${path}`), env, {});
    assert.equal(response.status, 302);
    assert.equal(response.headers.get('location'), 'https://example.com/login');
  }
  assert.equal(assetPaths.length, 0);
  const login = await api.handleApi(new Request('https://example.com/api/login', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: 'secret' }),
  }), env, {}, new URL('https://example.com/api/login'), 'api/login');
  const cookie = login.headers.get('set-cookie').split(';')[0];
  for (const path of ['/admin', '/admin/', '/admin.html']) {
    const response = await worker.fetch(new Request(`https://example.com${path}`, { headers: { Cookie: cookie } }), env, {});
    assert.equal(response.status, 200);
  }
  assert.deepEqual(assetPaths, ['/admin', '/admin', '/admin']);
});

test('webhook failures are logged for HTTP and provider errors', async () => {
  let response = new Response('{"errcode":0}');
  const { api, errors } = loadWorker(async () => response);
  const env = { NOTIFICATION_WEBHOOK_URL: 'https://example.com/hook' };
  await api.sendWebhookNotification(env, 'test');
  assert.equal(errors.length, 0);
  response = new Response('{}', { status: 500 });
  await api.sendWebhookNotification(env, 'test');
  response = new Response('{"errcode":400}');
  await api.sendWebhookNotification(env, 'test');
  assert.equal(errors.length, 2);
});

test('Telegram notifications send with chat_id and log API errors', async () => {
  let sentBody = null;
  let sentUrl = null;
  const mockFetch = async (url, init) => {
    sentUrl = url;
    sentBody = JSON.parse(init.body);
    return new Response('{"ok":true}');
  };
  const { api, errors } = loadWorker(mockFetch);

  // 1. Via TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID
  await api.sendTelegramNotification({ TELEGRAM_BOT_TOKEN: 'token123', TELEGRAM_CHAT_ID: 'chat456' }, 'hello tg');
  assert.equal(sentUrl, 'https://api.telegram.org/bottoken123/sendMessage');
  assert.deepEqual(sentBody, { chat_id: 'chat456', text: 'hello tg' });
  assert.equal(errors.length, 0);

  // 2. Via NOTIFICATION_WEBHOOK_URL with query parameter chat_id
  await api.sendWebhookNotification({ NOTIFICATION_WEBHOOK_URL: 'https://api.telegram.org/bottoken123/sendMessage?chat_id=chat789' }, 'hello tg url');
  assert.deepEqual(sentBody, { chat_id: 'chat789', text: 'hello tg url' });

  // 3. Telegram API error handling
  const errorFetch = async () => new Response('{"ok":false,"error_code":400,"description":"Bad Request"}');
  const errorWorker = loadWorker(errorFetch);
  await errorWorker.api.sendTelegramNotification({ TELEGRAM_BOT_TOKEN: 'token', TELEGRAM_CHAT_ID: 'chat' }, 'fail');
  assert.equal(errorWorker.errors.length, 1);
});
