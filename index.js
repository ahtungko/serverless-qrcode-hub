let DB;
let dbInitPromise = null;

const RESERVED_PATHS = new Set([
  'api',
  'login',
  'admin',
  '__total_count',
  'admin.html',
  'login.html',
  'daisyui@5.css',
  'tailwindcss@4.js',
  'qr-code-styling.js',
  'zxing.js',
  'robots.txt',
  'wechat.svg',
  'favicon.svg',
]);

const SESSION_COOKIE = 'token';
const SESSION_MAX_AGE = 60 * 60 * 24;
const EXPIRING_DAYS = 3;
const EXPIRED_RETENTION_DAYS = 30;
const DEFAULT_PAGE_SIZE = 10;
const MAX_PAGE_SIZE = 100;
const MAX_QR_DATA_LENGTH = 500 * 1024;
const DEFAULT_WECHAT_ANNOUNCEMENT_HTML = '<p>请长按识别下方二维码</p>';
const DEFAULT_WECHAT_HINT_HTML = '<p>二维码失效请联系作者更新</p>';
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'SAMEORIGIN',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
};
const RICH_TEXT_TAG_MAP = {
  a: 'a',
  b: 'strong',
  br: 'br',
  div: 'div',
  em: 'em',
  i: 'em',
  li: 'li',
  ol: 'ol',
  p: 'p',
  span: 'span',
  strong: 'strong',
  u: 'u',
  ul: 'ul',
};

const SORT_FIELD_MAP = {
  created_at: 'created_at',
  updated_at: 'updated_at',
  expiry: 'expiry',
  visit_count: 'visit_count',
  path: 'path',
  name: 'name',
};

class AppError extends Error {
  constructor(message, status = 400, code = 'BAD_REQUEST') {
    super(message);
    this.status = status;
    this.code = code;
  }
}

function escapeHtml(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json;charset=UTF-8',
      'Cache-Control': 'no-store',
      ...SECURITY_HEADERS,
      ...headers,
    },
  });
}

function errorResponse(error) {
  const status = error instanceof AppError ? error.status : 500;
  const code = error instanceof AppError ? error.code : 'INTERNAL_ERROR';
  const message = error instanceof Error ? error.message : 'Internal Server Error';
  return json({ error: message, code }, status);
}

function getSessionSecret(env) {
  const secret = env.SESSION_SECRET || env.PASSWORD;
  if (!secret || typeof secret !== 'string' || !secret.trim()) {
    throw new AppError('系统未配置管理员密码 (PASSWORD)，请先在 Cloudflare 环境变量中设置', 500, 'CONFIG_ERROR');
  }
  return secret.trim();
}

function toBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function hmac(value, secret) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(value));
  return toBase64Url(signature);
}

async function createSessionToken(env) {
  const secret = getSessionSecret(env);
  const expiresAt = Date.now() + SESSION_MAX_AGE * 1000;
  const signature = await hmac(`admin-session:${expiresAt}`, secret);
  return `${expiresAt}.${signature}`;
}

function getCookieValue(cookieHeader, name) {
  if (!cookieHeader) {
    return '';
  }
  const parts = cookieHeader.split(';');
  for (const part of parts) {
    const [key, ...rest] = part.trim().split('=');
    if (key === name) {
      return rest.join('=');
    }
  }
  return '';
}

async function verifyAuthCookie(request, env) {
  const currentToken = getCookieValue(request.headers.get('Cookie') || '', SESSION_COOKIE);
  if (!currentToken || !currentToken.includes('.')) {
    return false;
  }
  const [expiresAtStr, signature] = currentToken.split('.');
  const expiresAt = Number(expiresAtStr);
  if (isNaN(expiresAt) || Date.now() > expiresAt) {
    return false;
  }
  try {
    const secret = getSessionSecret(env);
    const expectedSig = await hmac(`admin-session:${expiresAtStr}`, secret);
    return signature === expectedSig;
  } catch {
    return false;
  }
}

async function setAuthCookie(env) {
  const token = await createSessionToken(env);
  return {
    'Set-Cookie': `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_MAX_AGE}`,
  };
}

function clearAuthCookie() {
  return {
    'Set-Cookie': `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`,
  };
}

function getMalaysiaDate(dayOffset = 0) {
  // Malaysia Time (MYT) is UTC+08:00.
  const now = new Date(Date.now() + 8 * 60 * 60 * 1000);
  now.setUTCHours(0, 0, 0, 0);
  now.setUTCDate(now.getUTCDate() + dayOffset);
  return now.toISOString().slice(0, 10);
}

function normalizePath(value) {
  return String(value || '').trim().replace(/^\/+/, '');
}

function normalizeExpiry(value) {
  if (!value) {
    return null;
  }
  const text = String(value).trim();
  const dateText = text.slice(0, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(dateText)) {
    throw new AppError('有效日期格式不正确');
  }
  const parsed = new Date(`${dateText}T00:00:00.000Z`);
  if (Number.isNaN(parsed.getTime())) {
    throw new AppError('有效日期格式不正确');
  }
  return dateText;
}

function normalizeBoolean(value, defaultValue = false) {
  if (typeof value === 'boolean') {
    return value;
  }
  if (value === undefined || value === null || value === '') {
    return defaultValue;
  }
  if (typeof value === 'number') {
    return value === 1;
  }
  if (typeof value === 'string') {
    return ['1', 'true', 'yes', 'on'].includes(value.toLowerCase());
  }
  return defaultValue;
}

function assertValidTarget(target) {
  let parsed;
  try {
    parsed = new URL(target);
  } catch {
    throw new AppError('目标 URL 不合法');
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new AppError('目标 URL 仅支持 http 或 https');
  }
}

function sanitizeLinkHref(value) {
  const href = String(value || '').trim();
  if (!href) {
    return '';
  }
  if (/^(#|\/(?!\/)|\.\.?(\/|$))/i.test(href)) {
    return href;
  }
  try {
    const parsed = new URL(href);
    if (['http:', 'https:', 'mailto:', 'tel:'].includes(parsed.protocol)) {
      return href;
    }
  } catch {
  }
  return '';
}

function sanitizeRichText(value, fallback = '') {
  const source = String(value || '').trim();
  if (!source) {
    return fallback;
  }

  const tokens = source.matchAll(/<\/?([A-Za-z0-9]+)([^>]*)>/g);
  const stack = [];
  let lastIndex = 0;
  let output = '';

  for (const match of tokens) {
    output += escapeHtml(source.slice(lastIndex, match.index));
    lastIndex = match.index + match[0].length;

    const rawTag = String(match[1] || '').toLowerCase();
    const tag = RICH_TEXT_TAG_MAP[rawTag];
    if (!tag) {
      continue;
    }

    const isClosing = match[0][1] === '/';
    if (isClosing) {
      if (tag === 'br') {
        continue;
      }
      if (stack[stack.length - 1] === tag) {
        stack.pop();
        output += `</${tag}>`;
      }
      continue;
    }

    if (tag === 'br') {
      output += '<br>';
      continue;
    }

    if (tag === 'a') {
      const attrs = match[2] || '';
      const hrefMatch = attrs.match(/\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/i);
      const safeHref = sanitizeLinkHref(hrefMatch ? (hrefMatch[1] || hrefMatch[2] || hrefMatch[3] || '') : '');
      if (!safeHref) {
        continue;
      }
      const isExternal = !/^(#|\/|\.\.?(\/|$))/i.test(safeHref) && !/^mailto:|^tel:/i.test(safeHref);
      output += `<a href="${escapeHtml(safeHref)}"${isExternal ? ' target="_blank" rel="noopener noreferrer"' : ''}>`;
      stack.push('a');
      continue;
    }

    output += `<${tag}>`;
    stack.push(tag);
  }

  output += escapeHtml(source.slice(lastIndex));

  while (stack.length > 0) {
    output += `</${stack.pop()}>`;
  }

  const normalized = output
    .replace(/(?:&nbsp;|\u00A0)/g, ' ')
    .replace(/<div><\/div>/gi, '')
    .trim();

  return normalized || fallback;
}

function normalizeMappingPayload(payload, options = {}) {
  const path = normalizePath(payload.path);
  const target = String(payload.target || '').trim();
  const name = String(payload.name || '').trim();
  const expiry = normalizeExpiry(payload.expiry);
  const enabled = normalizeBoolean(payload.enabled, true);
  const isWechat = normalizeBoolean(payload.isWechat, false);
  const qrCodeData = payload.qrCodeData ? String(payload.qrCodeData).trim() : '';
  const announcementHtml = sanitizeRichText(payload.announcementHtml || payload.announcement_html || '', '');
  const hintHtml = sanitizeRichText(payload.hintHtml || payload.hint_html || '', '');

  if (!path) {
    throw new AppError('短链名不能为空');
  }
  if (!/^[A-Za-z0-9_-]+$/.test(path)) {
    throw new AppError('短链名只能包含字母、数字、下划线和横线');
  }
  if (RESERVED_PATHS.has(path)) {
    throw new AppError('该短链名已被系统保留，请使用其他名称');
  }
  if (!target) {
    throw new AppError('目标 URL 不能为空');
  }

  assertValidTarget(target);

  if (isWechat && !qrCodeData) {
    throw new AppError('微信二维码必须提供原始二维码数据');
  }

  if (qrCodeData && qrCodeData.length > MAX_QR_DATA_LENGTH) {
    throw new AppError('二维码图片数据过大（不能超过 500KB），请上传较小尺寸的图片');
  }

  const normalized = {
    path,
    target,
    name: name || null,
    expiry,
    enabled,
    isWechat,
    qrCodeData: isWechat ? qrCodeData : null,
    announcementHtml: announcementHtml || null,
    hintHtml: hintHtml || null,
  };

  if (options.includeMeta) {
    normalized.visitCount = Number(payload.visitCount || payload.visit_count || 0) || 0;
    normalized.lastVisitedAt = payload.lastVisitedAt || payload.last_visited_at || null;
    normalized.createdAt = payload.createdAt || payload.created_at || null;
    normalized.updatedAt = payload.updatedAt || payload.updated_at || null;
  }

  return normalized;
}

function isExpiredDate(expiry) {
  if (!expiry) {
    return false;
  }
  return expiry.slice(0, 10) < getMalaysiaDate();
}

function isExpiringDate(expiry) {
  if (!expiry) {
    return false;
  }
  const dateText = expiry.slice(0, 10);
  const today = getMalaysiaDate();
  return dateText >= today && dateText <= getMalaysiaDate(EXPIRING_DAYS);
}

function getMappingStatus(mapping) {
  if (!mapping.enabled) {
    return 'disabled';
  }
  if (mapping.expiry && isExpiredDate(mapping.expiry)) {
    return 'expired';
  }
  if (mapping.expiry && isExpiringDate(mapping.expiry)) {
    return 'expiring';
  }
  return 'active';
}

function serializeMapping(row) {
  const mapping = {
    path: row.path,
    target: row.target,
    name: row.name || '',
    expiry: row.expiry ? String(row.expiry).slice(0, 10) : '',
    enabled: row.enabled === 1 || row.enabled === true,
    isWechat: row.isWechat === 1 || row.isWechat === true,
    qrCodeData: row.qrCodeData || '',
    announcementHtml: row.announcementHtml || row.announcement_html || '',
    hintHtml: row.hintHtml || row.hint_html || '',
    visitCount: Number(row.visit_count || row.visitCount || 0) || 0,
    lastVisitedAt: row.last_visited_at || row.lastVisitedAt || '',
    createdAt: row.created_at || row.createdAt || '',
    updatedAt: row.updated_at || row.updatedAt || '',
  };
  mapping.status = getMappingStatus(mapping);
  return mapping;
}

function parseListParams(searchParams) {
  const page = Math.max(Number(searchParams.get('page') || 1) || 1, 1);
  const pageSize = Math.min(
    Math.max(Number(searchParams.get('pageSize') || DEFAULT_PAGE_SIZE) || DEFAULT_PAGE_SIZE, 1),
    MAX_PAGE_SIZE
  );
  const query = String(searchParams.get('query') || '').trim().toLowerCase();
  const status = String(searchParams.get('status') || 'all').trim();
  const type = String(searchParams.get('type') || 'all').trim();
  const sortBy = SORT_FIELD_MAP[searchParams.get('sortBy')] ? searchParams.get('sortBy') : 'created_at';
  const sortOrder = String(searchParams.get('sortOrder') || 'desc').toLowerCase() === 'asc' ? 'asc' : 'desc';
  return { page, pageSize, query, status, type, sortBy, sortOrder };
}

function buildFilterQuery(filters) {
  const where = [`path NOT IN (${Array.from(RESERVED_PATHS).map(() => '?').join(',')})`];
  const bindings = Array.from(RESERVED_PATHS);
  const today = getMalaysiaDate();
  const expiringLimit = getMalaysiaDate(EXPIRING_DAYS);

  if (filters.query) {
    const keyword = `%${filters.query}%`;
    where.push(`(
      lower(path) LIKE ?
      OR lower(COALESCE(name, '')) LIKE ?
      OR lower(target) LIKE ?
    )`);
    bindings.push(keyword, keyword, keyword);
  }

  if (filters.type === 'wechat') {
    where.push('isWechat = 1');
  } else if (filters.type === 'normal') {
    where.push('isWechat = 0');
  }

  if (filters.status === 'active') {
    where.push('(enabled = 1 AND (expiry IS NULL OR substr(expiry, 1, 10) > ?))');
    bindings.push(expiringLimit);
  } else if (filters.status === 'expiring') {
    where.push('(enabled = 1 AND expiry IS NOT NULL AND substr(expiry, 1, 10) >= ? AND substr(expiry, 1, 10) <= ?)');
    bindings.push(today, expiringLimit);
  } else if (filters.status === 'expired') {
    where.push('(enabled = 1 AND expiry IS NOT NULL AND substr(expiry, 1, 10) < ?)');
    bindings.push(today);
  } else if (filters.status === 'disabled') {
    where.push('(enabled = 0)');
  }

  return { where: where.join(' AND '), bindings };
}

async function ensureDatabase(database = DB) {
  if (!database) {
    throw new AppError('D1 数据库未绑定 (DB)', 500, 'DATABASE_NOT_CONFIGURED');
  }
  if (!dbInitPromise) {
    dbInitPromise = initDatabase(database).catch((err) => {
      dbInitPromise = null;
      throw err;
    });
  }
  return dbInitPromise;
}

async function initDatabase(database = DB) {
  await database.prepare(`
    CREATE TABLE IF NOT EXISTS mappings (
      path TEXT PRIMARY KEY,
      target TEXT NOT NULL,
      name TEXT,
      expiry TEXT,
      enabled INTEGER DEFAULT 1,
      isWechat INTEGER DEFAULT 0,
      qrCodeData TEXT,
      announcementHtml TEXT,
      hintHtml TEXT,
      visit_count INTEGER DEFAULT 0,
      last_visited_at TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  const tableInfo = await database.prepare('PRAGMA table_info(mappings)').all();
  const columns = new Set((tableInfo.results || []).map((column) => column.name));

  // Another isolate may add the column after our schema inspection.
  async function addColumn(name, definition) {
    if (columns.has(name)) return;
    try {
      await database.prepare(`ALTER TABLE mappings ADD COLUMN ${name} ${definition}`).run();
    } catch (error) {
      const current = await database.prepare('PRAGMA table_info(mappings)').all();
      if (!(current.results || []).some((column) => column.name === name)) throw error;
    }
  }

  await addColumn('isWechat', 'INTEGER DEFAULT 0');
  await addColumn('qrCodeData', 'TEXT');
  await addColumn('announcementHtml', 'TEXT');
  await addColumn('hintHtml', 'TEXT');
  await addColumn('visit_count', 'INTEGER DEFAULT 0');
  await addColumn('last_visited_at', 'TEXT');
  await addColumn('updated_at', 'TEXT');

  await database.prepare(`
    UPDATE mappings
    SET updated_at = COALESCE(updated_at, created_at, CURRENT_TIMESTAMP)
    WHERE updated_at IS NULL OR updated_at = ''
  `).run();

  await database.prepare('CREATE INDEX IF NOT EXISTS idx_mappings_expiry ON mappings(expiry)').run();
  await database.prepare('CREATE INDEX IF NOT EXISTS idx_mappings_created_at ON mappings(created_at)').run();
  await database.prepare('CREATE INDEX IF NOT EXISTS idx_mappings_updated_at ON mappings(updated_at)').run();
  await database.prepare('CREATE INDEX IF NOT EXISTS idx_mappings_enabled_expiry ON mappings(enabled, expiry)').run();
  await database.prepare('CREATE INDEX IF NOT EXISTS idx_mappings_visit_count ON mappings(visit_count)').run();
  await database.prepare('CREATE INDEX IF NOT EXISTS idx_mappings_is_wechat ON mappings(isWechat)').run();
}

async function getMappingByPath(path) {
  const mapping = await DB.prepare(`
    SELECT path, target, name, expiry, enabled, isWechat, qrCodeData, announcementHtml, hintHtml, visit_count, last_visited_at, created_at, updated_at
    FROM mappings
    WHERE path = ?
  `).bind(path).first();
  return mapping ? serializeMapping(mapping) : null;
}

async function ensurePathAvailable(path, originalPath = '') {
  const existing = await DB.prepare('SELECT path FROM mappings WHERE path = ?').bind(path).first();
  if (existing && existing.path !== originalPath) {
    throw new AppError('短链名已存在', 409, 'PATH_CONFLICT');
  }
}

async function createMapping(payload, options = {}) {
  const mapping = normalizeMappingPayload(payload, { includeMeta: options.includeMeta });
  await ensurePathAvailable(mapping.path);

  if (options.includeMeta) {
    await DB.prepare(`
      INSERT INTO mappings (
        path, target, name, expiry, enabled, isWechat, qrCodeData, announcementHtml, hintHtml,
        visit_count, last_visited_at, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      mapping.path,
      mapping.target,
      mapping.name,
      mapping.expiry,
      mapping.enabled ? 1 : 0,
      mapping.isWechat ? 1 : 0,
      mapping.qrCodeData,
      mapping.announcementHtml,
      mapping.hintHtml,
      mapping.visitCount,
      mapping.lastVisitedAt,
      mapping.createdAt || new Date().toISOString(),
      mapping.updatedAt || mapping.createdAt || new Date().toISOString()
    ).run();
  } else {
    await DB.prepare(`
      INSERT INTO mappings (path, target, name, expiry, enabled, isWechat, qrCodeData, announcementHtml, hintHtml, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      mapping.path,
      mapping.target,
      mapping.name,
      mapping.expiry,
      mapping.enabled ? 1 : 0,
      mapping.isWechat ? 1 : 0,
      mapping.qrCodeData,
      mapping.announcementHtml,
      mapping.hintHtml,
      new Date().toISOString()
    ).run();
  }

  return getMappingByPath(mapping.path);
}

async function updateMapping(payload) {
  const originalPath = normalizePath(payload.originalPath);
  if (!originalPath) {
    throw new AppError('原短链名不能为空');
  }

  const current = await getMappingByPath(originalPath);
  if (!current) {
    throw new AppError('映射不存在', 404, 'NOT_FOUND');
  }

  const mapping = normalizeMappingPayload(payload);
  await ensurePathAvailable(mapping.path, originalPath);

  const qrCodeData = mapping.isWechat
    ? (mapping.qrCodeData || current.qrCodeData || null)
    : null;

  if (mapping.isWechat && !qrCodeData) {
    throw new AppError('微信二维码必须提供原始二维码数据');
  }

  await DB.prepare(`
    UPDATE mappings
    SET path = ?, target = ?, name = ?, expiry = ?, enabled = ?, isWechat = ?, qrCodeData = ?, announcementHtml = ?, hintHtml = ?, updated_at = ?
    WHERE path = ?
  `).bind(
    mapping.path,
    mapping.target,
    mapping.name,
    mapping.expiry,
    mapping.enabled ? 1 : 0,
    mapping.isWechat ? 1 : 0,
    qrCodeData,
    mapping.announcementHtml,
    mapping.hintHtml,
    new Date().toISOString(),
    originalPath
  ).run();

  return getMappingByPath(mapping.path);
}

async function deleteMapping(path) {
  const normalizedPath = normalizePath(path);
  if (!normalizedPath) {
    throw new AppError('短链名不能为空');
  }
  if (RESERVED_PATHS.has(normalizedPath)) {
    throw new AppError('系统保留的短链名无法删除');
  }
  const existing = await getMappingByPath(normalizedPath);
  if (!existing) {
    throw new AppError('映射不存在', 404, 'NOT_FOUND');
  }
  await DB.prepare('DELETE FROM mappings WHERE path = ?').bind(normalizedPath).run();
  return existing;
}

async function bulkDeleteMappings(paths) {
  if (!Array.isArray(paths) || paths.length === 0) {
    throw new AppError('请选择至少一个短链');
  }
  const normalized = [...new Set(paths.map((item) => normalizePath(item)).filter(Boolean))];
  const failures = [];
  const removable = [];

  for (const path of normalized) {
    if (RESERVED_PATHS.has(path)) {
      failures.push({ path, error: '系统保留的短链无法删除' });
      continue;
    }
    removable.push(path);
  }

  if (removable.length > 0) {
    const placeholders = removable.map(() => '?').join(',');
    await DB.prepare(`DELETE FROM mappings WHERE path IN (${placeholders})`).bind(...removable).run();
  }

  return {
    deletedCount: removable.length,
    deletedPaths: removable,
    failures,
  };
}

async function listMappings(filters) {
  const { where, bindings } = buildFilterQuery(filters);
  const sortBy = SORT_FIELD_MAP[filters.sortBy] || SORT_FIELD_MAP.created_at;
  const sortOrder = filters.sortOrder === 'asc' ? 'ASC' : 'DESC';
  const offset = (filters.page - 1) * filters.pageSize;

  const totalResult = await DB.prepare(`SELECT COUNT(*) AS total FROM mappings WHERE ${where}`).bind(...bindings).first();
  const rows = await DB.prepare(`
    SELECT path, target, name, expiry, enabled, isWechat, qrCodeData, announcementHtml, hintHtml, visit_count, last_visited_at, created_at, updated_at
    FROM mappings
    WHERE ${where}
    ORDER BY ${sortBy} ${sortOrder}, created_at DESC
    LIMIT ? OFFSET ?
  `).bind(...bindings, filters.pageSize, offset).all();

  const items = (rows.results || []).map(serializeMapping);
  const totalItems = Number(totalResult?.total || 0);
  const totalPages = totalItems === 0 ? 0 : Math.ceil(totalItems / filters.pageSize);

  return {
    items,
    pagination: {
      page: filters.page,
      pageSize: filters.pageSize,
      totalItems,
      totalPages,
    },
    summary: {
      query: filters.query,
      status: filters.status,
      type: filters.type,
      sortBy: filters.sortBy,
      sortOrder: filters.sortOrder,
      selectedCount: items.length,
    },
  };
}

async function getExpiringMappings() {
  const expiring = await listMappings({
    page: 1,
    pageSize: MAX_PAGE_SIZE,
    query: '',
    status: 'expiring',
    type: 'all',
    sortBy: 'expiry',
    sortOrder: 'asc',
  });
  const expired = await listMappings({
    page: 1,
    pageSize: MAX_PAGE_SIZE,
    query: '',
    status: 'expired',
    type: 'all',
    sortBy: 'expiry',
    sortOrder: 'asc',
  });
  return {
    expiring: expiring.items,
    expired: expired.items,
    expiringTotal: expiring.pagination.totalItems,
    expiredTotal: expired.pagination.totalItems,
  };
}

async function getDashboard() {
  const today = getMalaysiaDate();
  const expiringLimit = getMalaysiaDate(EXPIRING_DAYS);
  const bindings = Array.from(RESERVED_PATHS);
  const reservedPlaceholders = bindings.map(() => '?').join(',');

  const stats = await DB.prepare(`
    SELECT
      COUNT(*) AS total,
      SUM(CASE WHEN enabled = 1 AND (expiry IS NULL OR substr(expiry, 1, 10) > ?) THEN 1 ELSE 0 END) AS active_total,
      SUM(CASE WHEN enabled = 0 THEN 1 ELSE 0 END) AS disabled_total,
      SUM(CASE WHEN enabled = 1 AND expiry IS NOT NULL AND substr(expiry, 1, 10) < ? THEN 1 ELSE 0 END) AS expired_total,
      SUM(CASE WHEN enabled = 1 AND expiry IS NOT NULL AND substr(expiry, 1, 10) >= ? AND substr(expiry, 1, 10) <= ? THEN 1 ELSE 0 END) AS expiring_total,
      SUM(CASE WHEN isWechat = 1 THEN 1 ELSE 0 END) AS wechat_total,
      SUM(COALESCE(visit_count, 0)) AS visit_total
    FROM mappings
    WHERE path NOT IN (${reservedPlaceholders})
  `).bind(expiringLimit, today, today, expiringLimit, ...bindings).first();

  const topVisited = await DB.prepare(`
    SELECT path, target, name, expiry, enabled, isWechat, qrCodeData, announcementHtml, hintHtml, visit_count, last_visited_at, created_at, updated_at
    FROM mappings
    WHERE path NOT IN (${reservedPlaceholders})
    ORDER BY visit_count DESC, updated_at DESC
    LIMIT 5
  `).bind(...bindings).all();

  return {
    total: Number(stats?.total || 0),
    active: Number(stats?.active_total || 0),
    disabled: Number(stats?.disabled_total || 0),
    expiring: Number(stats?.expiring_total || 0),
    expired: Number(stats?.expired_total || 0),
    wechat: Number(stats?.wechat_total || 0),
    visits: Number(stats?.visit_total || 0),
    topVisited: (topVisited.results || []).map(serializeMapping),
  };
}

async function exportMappings() {
  const bindings = Array.from(RESERVED_PATHS);
  const placeholders = bindings.map(() => '?').join(',');
  const rows = await DB.prepare(`
    SELECT path, target, name, expiry, enabled, isWechat, qrCodeData, announcementHtml, hintHtml, visit_count, last_visited_at, created_at, updated_at
    FROM mappings
    WHERE path NOT IN (${placeholders})
    ORDER BY created_at DESC
  `).bind(...bindings).all();
  return (rows.results || []).map(serializeMapping);
}

async function importMappings(items) {
  if (!Array.isArray(items) || items.length === 0) {
    throw new AppError('导入数据不能为空');
  }

  const failures = [];
  let successCount = 0;

  for (const item of items) {
    try {
      await createMapping(item, { includeMeta: true });
      successCount += 1;
    } catch (error) {
      failures.push({
        path: normalizePath(item?.path),
        error: error instanceof Error ? error.message : '导入失败',
      });
    }
  }

  return {
    successCount,
    failureCount: failures.length,
    failures,
  };
}

async function cleanupExpiredMappings() {
  const cutoff = getMalaysiaDate(-EXPIRED_RETENTION_DAYS);
  const result = await DB.prepare(`
    DELETE FROM mappings
    WHERE expiry IS NOT NULL AND substr(expiry, 1, 10) < ?
  `).bind(cutoff).run();
  return Number(result.meta?.changes || 0);
}

async function trackVisit(path) {
  try {
    await DB.prepare(`
      UPDATE mappings
      SET visit_count = COALESCE(visit_count, 0) + 1,
          last_visited_at = ?
      WHERE path = ?
    `).bind(new Date().toISOString(), path).run();
  } catch (error) {
    console.error(`Failed to track visit for path "${path}":`, error);
  }
}

async function sendWebhookNotification(env, message) {
  const webhookUrl = env.NOTIFICATION_WEBHOOK_URL;
  if (!webhookUrl) {
    return;
  }
  try {
    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        msgtype: 'text',
        text: { content: message },
        msg_type: 'text',
        content: { text: message },
      }),
    });
    if (!response.ok) throw new Error(`Webhook returned HTTP ${response.status}`);
    const result = await response.json();
    const code = result.errcode ?? result.code ?? result.StatusCode;
    if (code !== undefined && Number(code) !== 0) {
      throw new Error(`Webhook rejected notification (code: ${String(code).slice(0, 100)})`);
    }
  } catch (error) {
    console.error('Failed to send webhook notification:', error);
  }
}

async function readRequestJson(request) {
  try {
    return await request.json();
  } catch {
    throw new AppError('请求数据格式不正确');
  }
}

async function serveAsset(request, env, url, path) {
  if (!env.ASSETS || typeof env.ASSETS.fetch !== 'function') {
    return new Response('Not Found', { status: 404 });
  }
  let targetUrl = new URL(request.url);
  if (path === 'admin') {
    targetUrl = new URL('/admin.html', url.origin);
  } else if (path === 'login') {
    targetUrl = new URL('/login.html', url.origin);
  }
  return env.ASSETS.fetch(new Request(targetUrl.toString(), request));
}

function shouldServeAssetFirst(path) {
  return !path || path === 'admin' || path === 'login' || path.includes('.') || RESERVED_PATHS.has(path);
}

function createDisabledHtml(mapping) {
  const title = escapeHtml(mapping.name ? `${mapping.name} 已暂停访问` : '链接已暂停访问');
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title}</title>
  <style>
    :root { color-scheme: light dark; }
    body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 24px; background: #f5f5f5; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    .card { width: min(100%, 360px); padding: 28px 24px; text-align: center; background: #fff; border-radius: 18px; box-shadow: 0 12px 32px rgba(15, 23, 42, 0.08); }
    h1 { margin: 0 0 12px; font-size: 22px; color: #111827; }
    p { margin: 8px 0; color: #6b7280; line-height: 1.6; }
    @media (prefers-color-scheme: dark) {
      body { background: #0f172a; }
      .card { background: #111827; box-shadow: none; }
      h1 { color: #f8fafc; }
      p { color: #cbd5e1; }
    }
  </style>
</head>
<body>
  <div class="card">
    <h1>${title}</h1>
    <p>该链接已被管理员暂停使用。</p>
    <p>如需继续访问，请联系管理员开启。</p>
  </div>
</body>
</html>`;
}

function createExpiredHtml(mapping) {
  const title = escapeHtml(mapping.name ? `${mapping.name} 已过期` : '链接已过期');
  const expiry = escapeHtml(mapping.expiry || '');
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title}</title>
  <style>
    :root { color-scheme: light dark; }
    body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 24px; background: #f5f5f5; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    .card { width: min(100%, 360px); padding: 28px 24px; text-align: center; background: #fff; border-radius: 18px; box-shadow: 0 12px 32px rgba(15, 23, 42, 0.08); }
    h1 { margin: 0 0 12px; font-size: 24px; color: #111827; }
    p { margin: 8px 0; color: #6b7280; line-height: 1.6; }
    @media (prefers-color-scheme: dark) {
      body { background: #0f172a; }
      .card { background: #111827; box-shadow: none; }
      h1 { color: #f8fafc; }
      p { color: #cbd5e1; }
    }
  </style>
</head>
<body>
  <div class="card">
    <h1>${title}</h1>
    <p>过期时间：${expiry || '未设置'}</p>
    <p>如需继续访问，请联系管理员更新链接。</p>
  </div>
</body>
</html>`;
}

function createWechatHtml(mapping) {
  const title = escapeHtml(mapping.name || '微信群二维码');
  const announcementHtml = sanitizeRichText(mapping.announcementHtml || mapping.announcement_html || '', DEFAULT_WECHAT_ANNOUNCEMENT_HTML);
  const hintHtml = sanitizeRichText(mapping.hintHtml || mapping.hint_html || '', DEFAULT_WECHAT_HINT_HTML);
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title}</title>
  <style>
    :root { color-scheme: light dark; }
    body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 24px; background: #f5f5f5; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    .card { width: min(100%, 420px); padding: 28px 24px; text-align: center; background: #fff; border-radius: 18px; box-shadow: 0 12px 32px rgba(15, 23, 42, 0.08); }
    .icon { width: 40px; height: 40px; margin-bottom: 12px; }
    h1 { margin: 0 0 8px; font-size: 24px; color: #111827; }
    .rich-text { color: #6b7280; line-height: 1.7; }
    .rich-text :where(p, div, ul, ol) { margin: 10px 0 0; }
    .rich-text :where(p, div, ul, ol):first-child { margin-top: 0; }
    .rich-text :where(ul, ol) { padding-left: 1.4em; text-align: left; }
    .rich-text :where(li + li) { margin-top: 0.35em; }
    .rich-text a { color: #2563eb; text-decoration: underline; }
    img.qr { width: 100%; max-width: 260px; margin: 18px auto 0; border-radius: 16px; display: block; background: #fff; }
    @media (prefers-color-scheme: dark) {
      body { background: #0f172a; }
      .card { background: #111827; box-shadow: none; }
      h1 { color: #f8fafc; }
      .rich-text { color: #cbd5e1; }
      .rich-text a { color: #93c5fd; }
    }
  </style>
</head>
<body>
  <div class="card">
    <img class="icon" src="/wechat.svg" alt="WeChat">
    <h1>${title}</h1>
    <div class="rich-text">${announcementHtml}</div>
    <img class="qr" src="${escapeHtml(mapping.qrCodeData || '')}" alt="微信群二维码">
    <div class="rich-text">${hintHtml}</div>
  </div>
</body>
</html>`;
}

async function handleApi(request, env, ctx, url, path) {
  if (path === 'api/login') {
    if (request.method !== 'POST') {
      return json({ error: 'Method Not Allowed' }, 405);
    }
    try {
      const body = await readRequestJson(request);
      const configuredPassword = env.PASSWORD;
      if (!configuredPassword || typeof configuredPassword !== 'string' || !configuredPassword.trim()) {
        throw new AppError('系统未配置管理员密码 (PASSWORD)，请先在 Cloudflare 环境变量中设置', 500, 'CONFIG_ERROR');
      }
      const inputPassword = String(body.password || '');
      if (inputPassword !== configuredPassword.trim()) {
        throw new AppError('密码错误，请重试', 401, 'UNAUTHORIZED');
      }
      return json({ success: true }, 200, await setAuthCookie(env));
    } catch (error) {
      return errorResponse(error);
    }
  }

  if (path === 'api/logout') {
    if (request.method !== 'POST') {
      return json({ error: 'Method Not Allowed' }, 405);
    }
    return json({ success: true }, 200, clearAuthCookie());
  }

  if (path === 'api/session') {
    const authenticated = await verifyAuthCookie(request, env);
    if (!authenticated) {
      return json({ error: 'Unauthorized', authenticated: false }, 401);
    }
    return json({ authenticated: true });
  }

  if (!(await verifyAuthCookie(request, env))) {
    return json({ error: 'Unauthorized' }, 401);
  }

  try {
    if (path === 'api/dashboard' && request.method === 'GET') {
      return json(await getDashboard());
    }

    if (path === 'api/expiring-mappings' && request.method === 'GET') {
      return json(await getExpiringMappings());
    }

    if (path === 'api/mappings' && request.method === 'GET') {
      return json(await listMappings(parseListParams(url.searchParams)));
    }

    if (path === 'api/mappings/export' && request.method === 'GET') {
      const exported = await exportMappings();
      const filename = `mappings-${getMalaysiaDate().replace(/-/g, '')}.json`;
      return new Response(JSON.stringify({ items: exported }, null, 2), {
        headers: {
          'Content-Type': 'application/json;charset=UTF-8',
          'Content-Disposition': `attachment; filename="${filename}"`,
          'Cache-Control': 'no-store',
          ...SECURITY_HEADERS,
        },
      });
    }

    if (path === 'api/mappings/import' && request.method === 'POST') {
      const body = await readRequestJson(request);
      const items = Array.isArray(body) ? body : body.items;
      return json(await importMappings(items));
    }

    if (path === 'api/mappings/bulk-delete' && request.method === 'POST') {
      const body = await readRequestJson(request);
      return json(await bulkDeleteMappings(body.paths));
    }

    if (path === 'api/mapping') {
      if (request.method === 'GET') {
        const mappingPath = normalizePath(url.searchParams.get('path'));
        if (!mappingPath) {
          throw new AppError('缺少 path 参数');
        }
        const mapping = await getMappingByPath(mappingPath);
        if (!mapping) {
          throw new AppError('映射不存在', 404, 'NOT_FOUND');
        }
        return json(mapping);
      }

      if (request.method === 'POST') {
        return json(await createMapping(await readRequestJson(request)), 201);
      }

      if (request.method === 'PUT') {
        return json(await updateMapping(await readRequestJson(request)));
      }

      if (request.method === 'DELETE') {
        const body = await readRequestJson(request);
        return json(await deleteMapping(body.path));
      }
    }

    return json({ error: 'Not Found' }, 404);
  } catch (error) {
    return errorResponse(error);
  }
}

async function handleMappingRequest(path, env, ctx) {
  const mapping = await getMappingByPath(path);
  if (!mapping) {
    return null;
  }

  if (!mapping.enabled) {
    return new Response(createDisabledHtml(mapping), {
      status: 403,
      headers: {
        'Content-Type': 'text/html;charset=UTF-8',
        'Cache-Control': 'no-store',
        ...SECURITY_HEADERS,
      },
    });
  }

  if (mapping.expiry && isExpiredDate(mapping.expiry)) {
    return new Response(createExpiredHtml(mapping), {
      status: 404,
      headers: {
        'Content-Type': 'text/html;charset=UTF-8',
        'Cache-Control': 'no-store',
        ...SECURITY_HEADERS,
      },
    });
  }

  ctx.waitUntil(trackVisit(path));

  if (mapping.isWechat && mapping.qrCodeData) {
    return new Response(createWechatHtml(mapping), {
      headers: {
        'Content-Type': 'text/html;charset=UTF-8',
        'Cache-Control': 'no-store',
        ...SECURITY_HEADERS,
      },
    });
  }

  return Response.redirect(mapping.target, 302);
}

export default {
  async fetch(request, env, ctx) {
    DB = env.DB;

    const url = new URL(request.url);
    const path = normalizePath(url.pathname);

    if (!path) {
      return Response.redirect(`${url.origin}/admin`, 302);
    }

    if (path === 'admin') {
      const isAuthenticated = await verifyAuthCookie(request, env);
      if (!isAuthenticated) {
        return Response.redirect(`${url.origin}/login`, 302);
      }
      return serveAsset(request, env, url, path);
    }

    if (path === 'login') {
      const isAuthenticated = await verifyAuthCookie(request, env);
      if (isAuthenticated) {
        return Response.redirect(`${url.origin}/admin`, 302);
      }
      return serveAsset(request, env, url, path);
    }

    if (shouldServeAssetFirst(path)) {
      return serveAsset(request, env, url, path);
    }

    await ensureDatabase(DB);

    if (path.startsWith('api/')) {
      return handleApi(request, env, ctx, url, path);
    }

    const mappingResponse = await handleMappingRequest(path, env, ctx);
    if (mappingResponse) {
      return mappingResponse;
    }

    return serveAsset(request, env, url, path);
  },

  async scheduled(controller, env) {
    DB = env.DB;
    await ensureDatabase(DB);
    const expiring = await getExpiringMappings();
    const cleanedCount = await cleanupExpiredMappings();
    console.log(JSON.stringify({
      expiringCount: expiring.expiringTotal,
      expiredCount: expiring.expiredTotal,
      cleanedCount,
    }));

    if (env.NOTIFICATION_WEBHOOK_URL && (expiring.expiring.length > 0 || expiring.expired.length > 0)) {
      const formatNames = (items, total, label) => {
        const names = items.slice(0, 5).map((m) => `• ${String(m.name || m.path).slice(0, 20)} (${label}: ${m.expiry})`).join('\n');
        return names + (total > 5 ? `\n（仅显示前 5 条，共 ${total} 条）` : '');
      };
      const expiringNames = formatNames(expiring.expiring, expiring.expiringTotal, '到期');
      const expiredNames = formatNames(expiring.expired, expiring.expiredTotal, '已到期');
      let msg = `【QRCode Hub 提醒】\n`;
      if (expiring.expiring.length > 0) {
        msg += `有 ${expiring.expiringTotal} 个二维码即将失效：\n${expiringNames}\n`;
      }
      if (expiring.expired.length > 0) {
        msg += `有 ${expiring.expiredTotal} 个二维码已失效：\n${expiredNames}\n`;
      }
      await sendWebhookNotification(env, msg.trim());
    }
  },
};
