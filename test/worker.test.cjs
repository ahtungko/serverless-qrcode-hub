const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const vm = require('node:vm');
const { DatabaseSync } = require('node:sqlite');
const { webcrypto } = require('node:crypto');

function loadWorker(fetchImpl = fetch) {
  const source = readFileSync(join(__dirname, '..', 'index.js'), 'utf8')
    .replace('export default {', 'globalThis.worker = {');
  const errors = [];
  const context = vm.createContext({
    Response, Request, URL, TextEncoder, crypto: webcrypto, btoa,
    fetch: fetchImpl, console: { log() {}, error: (...args) => errors.push(args) },
  });
  vm.runInContext(`${source}\nglobalThis.testApi = { handleApi, getDashboard, listMappings, getChinaDate, initDatabase, sendWebhookNotification, setDatabase: value => { DB = value; } };`, context);
  return { api: context.testApi, errors };
}

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
      ['active', 1, null], ['future', 1, api.getChinaDate(4)],
      ['today', 1, api.getChinaDate()], ['boundary', 1, api.getChinaDate(3)],
      ['expired', 1, api.getChinaDate(-1)], ['disabled', 0, api.getChinaDate(-1)],
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
