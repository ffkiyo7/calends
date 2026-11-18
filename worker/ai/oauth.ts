// MCP 的 OAuth 2.1 授权：让 claude.ai 自定义连接器这类只能走 OAuth 的客户端连接 /mcp。
// - 发现：/.well-known/oauth-protected-resource（RFC 9728）与 /.well-known/oauth-authorization-server（RFC 8414）。
// - 客户端自助注册（RFC 7591，公开客户端，不发 client_secret）；授权码流程强制 PKCE S256。
// - 授权要站长本人在确认页点「允许」：确认页需要已登录的会话，未登录先去 /login 再回来；站长在确认页选只读或读写。
// - 访问令牌 1 小时，刷新令牌 90 天、每次刷新轮换；库里只存 SHA-256。授权在后台「AI」页与 MCP 令牌并列，可随时吊销。
import { isAuthed, randomToken, sameOrigin, sha256 } from '../auth.ts';
import type { Env } from '../env.ts';
import { getSettings } from '../store.ts';
import { locale, t } from '../../shared/i18n.ts';
import { normalizeBasePath } from '../../shared/base.ts';
import { pkceMatches, redirectMatches, validChallenge, validRedirect, withParams } from './oauth-rules.ts';

const ACCESS_TTL = 3600;
const REFRESH_TTL = 90 * 86400;
const REQUEST_TTL_MS = 15 * 60_000;
const CODE_TTL_MS = 5 * 60_000;
/** 自助注册不需要登录：限制数量，并清掉一天内没有完成授权的注册 */
const MAX_CLIENTS = 200;
const STALE_CLIENT_MS = 86_400_000;
const TOUCH_MS = 3_600_000;

export type Scope = 'read' | 'write';

/**
 * 本站对外的地址（含安装前缀）。优先 SITE_URL；但客户端用别的域名（如 workers.dev 或旧域名）连进来时，
 * 资源地址必须与它填写的 MCP 地址一致，所以按请求的域名给。HTTPS 反代后容器里看到的是 http，按 X-Forwarded-Proto 改回。
 */
export function issuer(req: Request, env: Env): string {
  const u = new URL(req.url);
  const site = env.SITE_URL ? new URL(env.SITE_URL) : undefined;
  const base = site && site.host === u.host ? env.SITE_URL!.replace(/\/+$/, '') : `${u.protocol}//${u.host}${normalizeBasePath(env.BASE_PATH)}`;
  return req.headers.get('x-forwarded-proto') === 'https' ? base.replace(/^http:/, 'https:') : base;
}

/** /mcp 拒绝未带令牌的请求时，告诉客户端去哪里找授权信息 */
export const resourceMetadataUrl = (req: Request, env: Env) => `${issuer(req, env)}/.well-known/oauth-protected-resource/mcp`;

export const isOAuthPath = (path: string) => path.startsWith('/oauth/') || path.startsWith('/.well-known/oauth-');

const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-headers': 'authorization, content-type, mcp-protocol-version',
  'access-control-allow-methods': 'GET, POST, OPTIONS',
};
const NO_STORE = { 'cache-control': 'no-store', pragma: 'no-cache' };

const jsonOut = (data: unknown, status = 200) => Response.json(data, { status, headers: { ...CORS, ...NO_STORE } });
const oauthError = (error: string, description?: string, status = 400) =>
  jsonOut({ error, ...(description ? { error_description: description } : {}) }, status);

// ---------- 页面 ----------

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

/** 授权确认页、出错页：服务端直接渲染，不进前端包；禁止被嵌进别的网页（防点击劫持） */
function page(body: string, status = 200): Response {
  const html = `<!doctype html><html lang="${esc(locale())}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><title>${esc(t('server.oauth.pageTitle'))}</title><style>
:root{--bg:#f7f7f8;--card:#fff;--fg:#1c1c1e;--muted:#6b6b70;--line:#e3e3e6;--accent:#1c1c1e;--accent-fg:#fff}
@media (prefers-color-scheme:dark){:root{--bg:#111113;--card:#1c1c1f;--fg:#ededef;--muted:#9a9aa0;--line:#2e2e33;--accent:#ededef;--accent-fg:#111113}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif;padding:16px}
main{width:100%;max-width:420px;background:var(--card);border:1px solid var(--line);border-radius:16px;padding:24px}
h1{font-size:19px;line-height:1.35;margin:0 0 8px}p{margin:0 0 16px;color:var(--muted)}b{color:var(--fg);word-break:break-word}
fieldset{border:0;padding:0;margin:0 0 20px;display:grid;gap:8px}
label{display:flex;gap:10px;align-items:flex-start;border:1px solid var(--line);border-radius:12px;padding:12px;cursor:pointer}
label:has(input:checked){border-color:var(--fg)}input{margin:3px 0 0;accent-color:var(--accent)}
.row{display:flex;gap:8px}button{flex:1;min-height:44px;border-radius:12px;font:inherit;font-weight:600;cursor:pointer;border:1px solid var(--line);background:transparent;color:var(--fg)}
button.primary{background:var(--accent);color:var(--accent-fg);border-color:var(--accent)}small{display:block;margin-top:16px;color:var(--muted);font-size:13px}
</style></head><body><main>${body}</main></body></html>`;
  return new Response(html, {
    status,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      ...NO_STORE,
      'x-frame-options': 'DENY',
      // 不设 form-action：提交后要跳回客户端的回调地址（另一个域名或私有协议），浏览器会按 form-action 拦下跳转
      'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
      // 不能用 no-referrer：那样浏览器提交表单时会发 Origin: null，同源检查就会拒绝。same-origin 也不会把确认页地址带给回调站点
      'referrer-policy': 'same-origin',
    },
  });
}

const notice = (text: string, status = 400) => page(`<h1>${esc(t('server.oauth.pageTitle'))}</h1><p>${esc(text)}</p>`, status);

// ---------- 存储 ----------

interface ClientRow {
  id: string;
  name: string;
  redirect_uris: string;
}
interface RequestRow {
  id: string;
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  state: string | null;
  expires_at: number;
}

const getClient = (env: Env, id: string) => env.DB.prepare('SELECT id, name, redirect_uris FROM oauth_clients WHERE id = ?1').bind(id).first<ClientRow>();

const getRequest = async (env: Env, id: string) => {
  const row = await env.DB.prepare('SELECT * FROM oauth_requests WHERE id = ?1').bind(id).first<RequestRow>();
  return row && row.expires_at > Date.now() ? row : undefined;
};

/** 签发一组新令牌；refresh 时在同一行上轮换 */
async function newTokens() {
  const access = `cal_at_${randomToken(32)}`;
  const refresh = `cal_rt_${randomToken(32)}`;
  return { access, refresh, accessHash: await sha256(access), refreshHash: await sha256(refresh), now: Date.now() };
}

const tokenBody = (tk: { access: string; refresh: string }, scope: string) => ({
  access_token: tk.access,
  token_type: 'Bearer',
  expires_in: ACCESS_TTL,
  refresh_token: tk.refresh,
  scope,
});

export interface OAuthGrant {
  id: string;
  name: string;
  scope: Scope;
  createdAt: string;
  lastUsedAt?: string;
}

/** 后台「AI」页：已授权的客户端（刷新令牌过期的不列） */
export async function listGrants(env: Env): Promise<OAuthGrant[]> {
  const rows = await env.DB.prepare(
    'SELECT g.id, g.scope, g.created_at, g.last_used_at, c.name FROM oauth_grants g LEFT JOIN oauth_clients c ON c.id = g.client_id WHERE g.refresh_expires_at > ?1 ORDER BY g.created_at',
  )
    .bind(Date.now())
    .all<{ id: string; scope: Scope; created_at: number; last_used_at: number | null; name: string | null }>();
  return rows.results.map((r) => ({
    id: r.id,
    name: r.name ?? 'OAuth',
    scope: r.scope,
    createdAt: new Date(r.created_at).toISOString(),
    ...(r.last_used_at ? { lastUsedAt: new Date(r.last_used_at).toISOString() } : {}),
  }));
}

/** 吊销一项授权：访问令牌和刷新令牌一起失效；返回是否删到了 */
export async function revokeGrant(env: Env, id: string): Promise<boolean> {
  const r = await env.DB.prepare('DELETE FROM oauth_grants WHERE id = ?1').bind(id).run();
  return r.meta.changes > 0;
}

/** /mcp 校验 OAuth 访问令牌；通过时每小时最多记一次最后使用时间 */
export async function authenticateOAuth(env: Env, raw: string): Promise<{ id: string; name: string; scope: Scope; createdAt: string } | undefined> {
  if (!raw.startsWith('cal_at_')) return undefined;
  const now = Date.now();
  const row = await env.DB.prepare(
    'SELECT g.id, g.scope, g.created_at, g.last_used_at, c.name FROM oauth_grants g LEFT JOIN oauth_clients c ON c.id = g.client_id WHERE g.access_hash = ?1 AND g.access_expires_at > ?2',
  )
    .bind(await sha256(raw), now)
    .first<{ id: string; scope: Scope; created_at: number; last_used_at: number | null; name: string | null }>();
  if (!row) return undefined;
  if (!row.last_used_at || now - row.last_used_at > TOUCH_MS)
    await env.DB.prepare('UPDATE oauth_grants SET last_used_at = ?1 WHERE id = ?2').bind(now, row.id).run();
  return { id: row.id, name: row.name ?? 'OAuth', scope: row.scope === 'write' ? 'write' : 'read', createdAt: new Date(row.created_at).toISOString() };
}

// ---------- 端点 ----------

function protectedResource(base: string): Response {
  return jsonOut({
    resource: `${base}/mcp`,
    authorization_servers: [base],
    bearer_methods_supported: ['header'],
    resource_name: 'Calends',
  });
}

function serverMetadata(base: string): Response {
  return jsonOut({
    issuer: base,
    authorization_endpoint: `${base}/oauth/authorize`,
    token_endpoint: `${base}/oauth/token`,
    registration_endpoint: `${base}/oauth/register`,
    revocation_endpoint: `${base}/oauth/revoke`,
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
    revocation_endpoint_auth_methods_supported: ['none'],
    authorization_response_iss_parameter_supported: true,
  });
}

async function register(req: Request, env: Env): Promise<Response> {
  const body = (await req.json().catch(() => null)) as { redirect_uris?: unknown; client_name?: unknown } | null;
  const uris = body?.redirect_uris;
  if (!Array.isArray(uris) || !uris.length || uris.length > 10 || !uris.every(validRedirect))
    return oauthError('invalid_redirect_uri', 'redirect_uris must be https, loopback http or a private-use scheme, without a fragment');
  const now = Date.now();
  await env.DB.prepare('DELETE FROM oauth_clients WHERE created_at < ?1 AND id NOT IN (SELECT client_id FROM oauth_grants)')
    .bind(now - STALE_CLIENT_MS)
    .run();
  const count = await env.DB.prepare('SELECT COUNT(*) AS n FROM oauth_clients').first<{ n: number }>();
  if ((count?.n ?? 0) >= MAX_CLIENTS) return oauthError('invalid_client_metadata', 'too many registered clients', 429);
  const name = typeof body?.client_name === 'string' && body.client_name.trim() ? Array.from(body.client_name.trim()).slice(0, 60).join('') : 'MCP client';
  const id = `cal_client_${randomToken(16)}`;
  await env.DB.prepare('INSERT INTO oauth_clients (id, name, redirect_uris, created_at) VALUES (?1, ?2, ?3, ?4)')
    .bind(id, name, JSON.stringify(uris), now)
    .run();
  return jsonOut(
    {
      client_id: id,
      client_id_issued_at: Math.floor(now / 1000),
      client_name: name,
      redirect_uris: uris,
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
    },
    201,
  );
}

/** 第一步：校验授权请求，存下来，转到确认页（确认页地址不含回调参数，登录跳转只需带一个 id） */
async function authorize(req: Request, env: Env, base: string): Promise<Response> {
  const q = new URL(req.url).searchParams;
  const client = await getClient(env, q.get('client_id') ?? '');
  const registered = client ? (JSON.parse(client.redirect_uris) as string[]) : [];
  const asked = q.get('redirect_uri') ?? (registered.length === 1 ? registered[0] : '');
  const redirect = asked && registered.some((r) => redirectMatches(r, asked)) ? asked : undefined;
  // 客户端或回调地址不对时不能跳回去（可能被拿来做开放跳转），只能显示错误页
  if (!client || !redirect) return notice(t('server.oauth.badClient'));
  const state = q.get('state') ?? undefined;
  const back = (error: string, description: string) =>
    Response.redirect(withParams(redirect, { error, error_description: description, state, iss: base }), 302);
  if (q.get('response_type') !== 'code') return back('unsupported_response_type', 'only response_type=code is supported');
  if (q.get('code_challenge_method') !== 'S256' || !validChallenge(q.get('code_challenge'))) return back('invalid_request', 'PKCE with S256 is required');
  const id = randomToken(16);
  const now = Date.now();
  await env.DB.batch([
    env.DB.prepare('DELETE FROM oauth_requests WHERE expires_at < ?1').bind(now),
    env.DB.prepare('INSERT INTO oauth_requests (id, client_id, redirect_uri, code_challenge, state, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)').bind(
      id,
      client.id,
      redirect,
      q.get('code_challenge'),
      state ?? null,
      now + REQUEST_TTL_MS,
    ),
  ]);
  return Response.redirect(`${base}/oauth/consent/${id}`, 302);
}

/** 第二步：确认页。未登录先去登录页，登录后由前端整页跳回这里 */
async function consentPage(req: Request, env: Env, base: string, id: string): Promise<Response> {
  const request = await getRequest(env, id);
  const client = request && (await getClient(env, request.client_id));
  if (!request || !client) return notice(t('server.oauth.expired'));
  if (env.DEV_BYPASS_AUTH !== '1' && !(await isAuthed(req, env)))
    return Response.redirect(`${base}/login?next=${encodeURIComponent(`oauth/consent/${id}`)}`, 302);
  const host = new URL(request.redirect_uri).host || new URL(request.redirect_uri).protocol;
  const off = (await getSettings(env)).aiEnabled === false;
  const deny = `<button type="submit" name="decision" value="deny"${off ? ' class="primary"' : ''}>${esc(t('server.oauth.deny'))}</button>`;
  return page(
    `<form method="post" action="${esc(`${base}/oauth/consent/${id}`)}">
<h1>${esc(t('server.oauth.title', { client: client.name }))}</h1>
<p>${esc(t('server.oauth.redirect', { host })).replace(esc(host), `<b>${esc(host)}</b>`)}</p>
${
  off
    ? `<p>${esc(t('server.oauth.aiDisabled'))}</p><div class="row">${deny}</div>`
    : `<fieldset><label><input type="radio" name="scope" value="read" checked><span>${esc(t('server.oauth.scopeRead'))}</span></label>
<label><input type="radio" name="scope" value="write"><span>${esc(t('server.oauth.scopeWrite'))}</span></label></fieldset>
<div class="row">${deny}<button type="submit" name="decision" value="allow" class="primary">${esc(t('server.oauth.allow'))}</button></div>
<small>${esc(t('server.oauth.revokeHint'))}</small>`
}
</form>`,
  );
}

/** 第三步：站长的决定。只接受已登录、同源的表单提交；授权请求取出即作废，不能重复使用 */
async function consentDecision(req: Request, env: Env, base: string, id: string): Promise<Response> {
  const dev = env.DEV_BYPASS_AUTH === '1';
  if (!dev && (!sameOrigin(req) || !(await isAuthed(req, env)))) return notice(t('server.oauth.expired'), 403);
  const form = await req.formData().catch(() => undefined);
  const request = await env.DB.prepare('DELETE FROM oauth_requests WHERE id = ?1 RETURNING *').bind(id).first<RequestRow>();
  if (!request || request.expires_at <= Date.now()) return notice(t('server.oauth.expired'));
  const state = request.state ?? undefined;
  const allow = form?.get('decision') === 'allow' && (await getSettings(env)).aiEnabled !== false;
  if (!allow) return Response.redirect(withParams(request.redirect_uri, { error: 'access_denied', state, iss: base }), 303);
  const scope: Scope = form?.get('scope') === 'write' ? 'write' : 'read';
  const code = randomToken(32);
  const now = Date.now();
  await env.DB.batch([
    env.DB.prepare('DELETE FROM oauth_codes WHERE expires_at < ?1').bind(now),
    env.DB.prepare('INSERT INTO oauth_codes (code_hash, client_id, redirect_uri, code_challenge, scope, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)').bind(
      await sha256(code),
      request.client_id,
      request.redirect_uri,
      request.code_challenge,
      scope,
      now + CODE_TTL_MS,
    ),
  ]);
  return Response.redirect(withParams(request.redirect_uri, { code, state, iss: base }), 303);
}

async function readParams(req: Request): Promise<Record<string, string>> {
  const type = req.headers.get('content-type') ?? '';
  if (type.includes('application/json')) {
    const body = (await req.json().catch(() => ({}))) as Record<string, unknown>;
    return Object.fromEntries(Object.entries(body ?? {}).map(([k, v]) => [k, typeof v === 'string' ? v : '']));
  }
  return Object.fromEntries(new URLSearchParams(await req.text().catch(() => '')));
}

async function token(req: Request, env: Env): Promise<Response> {
  const p = await readParams(req);
  if (p.grant_type === 'authorization_code') {
    if (!p.code || !p.client_id || !p.redirect_uri) return oauthError('invalid_request', 'code, client_id and redirect_uri are required');
    // 取出即作废：同一个授权码只能换一次
    const row = await env.DB.prepare('DELETE FROM oauth_codes WHERE code_hash = ?1 RETURNING *')
      .bind(await sha256(p.code))
      .first<{ client_id: string; redirect_uri: string; code_challenge: string; scope: Scope; expires_at: number }>();
    if (!row || row.expires_at <= Date.now() || row.client_id !== p.client_id || row.redirect_uri !== p.redirect_uri)
      return oauthError('invalid_grant', 'authorization code is invalid or expired');
    if (!(await pkceMatches(p.code_verifier, row.code_challenge))) return oauthError('invalid_grant', 'code_verifier does not match');
    const tk = await newTokens();
    await env.DB.prepare(
      'INSERT INTO oauth_grants (id, client_id, scope, access_hash, access_expires_at, refresh_hash, refresh_expires_at, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)',
    )
      .bind(randomToken(8), row.client_id, row.scope, tk.accessHash, tk.now + ACCESS_TTL * 1000, tk.refreshHash, tk.now + REFRESH_TTL * 1000, tk.now)
      .run();
    return jsonOut(tokenBody(tk, row.scope));
  }
  if (p.grant_type === 'refresh_token') {
    if (!p.refresh_token) return oauthError('invalid_request', 'refresh_token is required');
    const hash = await sha256(p.refresh_token);
    const grant = await env.DB.prepare('SELECT id, client_id, scope FROM oauth_grants WHERE refresh_hash = ?1 AND refresh_expires_at > ?2')
      .bind(hash, Date.now())
      .first<{ id: string; client_id: string; scope: Scope }>();
    if (!grant || (p.client_id && p.client_id !== grant.client_id)) return oauthError('invalid_grant', 'refresh token is invalid or expired');
    const tk = await newTokens();
    // 条件更新：两个请求同时拿同一个刷新令牌来换，只有一个能成功
    const r = await env.DB.prepare(
      'UPDATE oauth_grants SET access_hash = ?1, access_expires_at = ?2, refresh_hash = ?3, refresh_expires_at = ?4 WHERE id = ?5 AND refresh_hash = ?6',
    )
      .bind(tk.accessHash, tk.now + ACCESS_TTL * 1000, tk.refreshHash, tk.now + REFRESH_TTL * 1000, grant.id, hash)
      .run();
    if (!r.meta.changes) return oauthError('invalid_grant', 'refresh token is invalid or expired');
    return jsonOut(tokenBody(tk, grant.scope));
  }
  return oauthError('unsupported_grant_type');
}

/** RFC 7009：不论令牌是否存在都回 200 */
async function revoke(req: Request, env: Env): Promise<Response> {
  const p = await readParams(req);
  if (p.token) {
    const hash = await sha256(p.token);
    await env.DB.prepare('DELETE FROM oauth_grants WHERE access_hash = ?1 OR refresh_hash = ?1').bind(hash).run();
  }
  return new Response(null, { status: 200, headers: { ...CORS, ...NO_STORE } });
}

/** 处理 OAuth 相关路径；不是这些路径时返回 undefined */
export async function oauth(req: Request, env: Env, path: string): Promise<Response | undefined> {
  const method = req.method;
  const base = issuer(req, env);
  if (method === 'OPTIONS' && (path.startsWith('/.well-known/') || ['/oauth/token', '/oauth/register', '/oauth/revoke'].includes(path)))
    return new Response(null, { status: 204, headers: CORS });
  if (method === 'GET' && (path === '/.well-known/oauth-protected-resource' || path === '/.well-known/oauth-protected-resource/mcp'))
    return protectedResource(base);
  if (method === 'GET' && (path === '/.well-known/oauth-authorization-server' || path === '/.well-known/oauth-authorization-server/mcp'))
    return serverMetadata(base);
  if (path === '/oauth/register' && method === 'POST') return register(req, env);
  if (path === '/oauth/authorize' && method === 'GET') return authorize(req, env, base);
  const consent = path.match(/^\/oauth\/consent\/([a-f0-9]{32})$/);
  if (consent && method === 'GET') return consentPage(req, env, base, consent[1]);
  if (consent && method === 'POST') return consentDecision(req, env, base, consent[1]);
  if (path === '/oauth/token' && method === 'POST') return token(req, env);
  if (path === '/oauth/revoke' && method === 'POST') return revoke(req, env);
  return undefined;
}
