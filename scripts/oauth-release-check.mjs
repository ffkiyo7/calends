// Isolated real-Worker OAuth check for /mcp. Run: node scripts/oauth-release-check.mjs
// Starts wrangler dev on a fresh temporary database with login enabled (no DEV_BYPASS_AUTH),
// walks discovery → registration → consent → token → MCP → refresh → revoke, and the refusal cases.
// Never accepts a remote URL or an existing database. Secrets stay in memory.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const SETUP = randomBytes(16).toString('hex');
const PASSWORD = randomBytes(12).toString('hex');
const CALLBACK = 'https://claude.ai/api/mcp/auth_callback';

async function freePort() {
  const s = createServer();
  await new Promise((r) => s.listen(0, '127.0.0.1', r));
  const port = s.address().port;
  await new Promise((r) => s.close(r));
  return port;
}

const b64url = (b) => b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const pkce = () => {
  const verifier = b64url(randomBytes(32));
  return { verifier, challenge: b64url(createHash('sha256').update(verifier).digest()) };
};

async function run(base) {
  // wrangler dev 可能改写请求地址，后续一律用相对路径拼本地地址，不信任文档里的绝对地址
  const local = (u) => `${base}${new URL(u, base).pathname}${new URL(u, base).search}`;
  const get = (path, headers = {}) => fetch(local(path), { redirect: 'manual', headers });
  const form = (path, data, headers = {}) =>
    fetch(local(path), {
      method: 'POST',
      redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
      body: new URLSearchParams(data),
    });
  const rpc = (token, method, params = {}) =>
    fetch(`${base}/mcp`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    });

  // 1. 首次设置密码，拿到站长会话
  const setup = await fetch(`${base}/api/auth/setup`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ setupToken: SETUP, password: PASSWORD }),
  });
  assert.equal(setup.status, 200, 'setup');
  const cookie = setup.headers.get('set-cookie').split(';')[0];
  const owner = { cookie };
  const state = await (await get('/api/state', owner)).json();
  assert.equal(state.subscriptions.length, 0, 'The instance must be new and empty');

  // 2. 未授权的 /mcp 指向资源元数据
  const anon = await fetch(`${base}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
  assert.equal(anon.status, 401);
  const wa = anon.headers.get('www-authenticate');
  const prmUrl = wa.match(/resource_metadata="([^"]+)"/)?.[1];
  assert.ok(prmUrl?.endsWith('/.well-known/oauth-protected-resource/mcp'), wa);
  const prm = await (await get(prmUrl)).json();
  assert.ok(prm.resource.endsWith('/mcp'));
  const as = await (await get(`${new URL(prm.authorization_servers[0]).pathname.replace(/\/$/, '')}/.well-known/oauth-authorization-server`)).json();
  assert.deepEqual(as.code_challenge_methods_supported, ['S256']);
  assert.deepEqual(as.token_endpoint_auth_methods_supported, ['none']);
  assert.equal(as.issuer, prm.authorization_servers[0]);
  console.log('PASS discovery: 401 resource_metadata, protected resource and authorization server metadata');

  // 3. 动态注册
  const badReg = await fetch(local(as.registration_endpoint), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ redirect_uris: ['http://evil.example/cb'] }),
  });
  assert.equal(badReg.status, 400);
  const reg = await fetch(local(as.registration_endpoint), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ client_name: 'Fictional Claude', redirect_uris: [CALLBACK], token_endpoint_auth_method: 'none' }),
  });
  assert.equal(reg.status, 201);
  const client = await reg.json();
  assert.equal(client.token_endpoint_auth_method, 'none');
  console.log('PASS registration: rejects non-loopback http, registers a public client');

  // 4. 授权请求
  const authUrl = (p, extra = {}) =>
    `${as.authorization_endpoint}?${new URLSearchParams({
      response_type: 'code',
      client_id: client.client_id,
      redirect_uri: CALLBACK,
      code_challenge: p.challenge,
      code_challenge_method: 'S256',
      state: 'st-1',
      resource: prm.resource,
      ...extra,
    })}`;
  // 回调地址不符、未知客户端：显示错误页，不跳转
  for (const bad of [authUrl(pkce(), { redirect_uri: 'https://evil.example/cb' }), authUrl(pkce(), { client_id: 'nope' })]) {
    const r = await get(bad);
    assert.equal(r.status, 400);
    assert.equal(r.headers.get('location'), null);
  }
  // 没有 PKCE：跳回客户端并带错误
  const noPkce = await get(authUrl(pkce(), { code_challenge_method: 'plain' }));
  assert.equal(noPkce.status, 302);
  assert.equal(new URL(noPkce.headers.get('location')).searchParams.get('error'), 'invalid_request');

  const flow = async (scope, decision = 'allow') => {
    const p = pkce();
    const r = await get(authUrl(p));
    assert.equal(r.status, 302);
    const consentPath = new URL(r.headers.get('location')).pathname;
    assert.match(consentPath, /\/oauth\/consent\/[a-f0-9]{32}$/);
    // 未登录：去登录页，登录后回到确认页
    const anonPage = await get(consentPath);
    assert.equal(anonPage.status, 302);
    assert.equal(new URL(anonPage.headers.get('location'), base).searchParams.get('next'), consentPath.replace(/^.*?(oauth\/consent\/)/, '$1'));
    // 未登录直接提交：拒绝
    assert.equal((await form(consentPath, { decision: 'allow', scope })).status, 403);
    // 已登录：确认页
    const pageRes = await get(consentPath, owner);
    assert.equal(pageRes.status, 200);
    assert.equal(pageRes.headers.get('x-frame-options'), 'DENY');
    // no-referrer 会让浏览器提交表单时发 Origin: null，被同源检查拒绝
    assert.equal(pageRes.headers.get('referrer-policy'), 'same-origin');
    assert.equal((await form(consentPath, { decision: 'allow', scope }, { ...owner, origin: 'null' })).status, 403);
    assert.ok((await pageRes.text()).includes('Fictional Claude'));
    // 跨站提交：拒绝
    assert.equal((await form(consentPath, { decision: 'allow', scope }, { ...owner, origin: 'https://evil.example' })).status, 403);
    // 浏览器提交同源表单时带的 Origin
    const done = await form(consentPath, { decision, scope }, { ...owner, origin: base });
    assert.equal(done.status, 303);
    const back = new URL(done.headers.get('location'));
    assert.equal(`${back.origin}${back.pathname}`, CALLBACK);
    assert.equal(back.searchParams.get('state'), 'st-1');
    // 同一个授权请求不能再用
    assert.equal((await form(consentPath, { decision: 'allow', scope }, owner)).status, 400);
    return { p, back };
  };

  const denied = await flow('read', 'deny');
  assert.equal(denied.back.searchParams.get('error'), 'access_denied');
  assert.equal(denied.back.searchParams.get('code'), null);

  const { p, back } = await flow('read');
  const code = back.searchParams.get('code');
  assert.ok(code);
  console.log('PASS consent: login redirect, unauthenticated and cross-site refusal, deny, single-use request');

  // 5. 换令牌
  const exchange = (extra = {}) =>
    form(as.token_endpoint, {
      grant_type: 'authorization_code',
      code,
      client_id: client.client_id,
      redirect_uri: CALLBACK,
      code_verifier: p.verifier,
      ...extra,
    });
  assert.equal((await exchange({ code: 'wrong' })).status, 400);
  // verifier 错误：授权码同时作废
  assert.equal((await exchange({ code_verifier: pkce().verifier })).status, 400);
  assert.equal((await exchange()).status, 400, 'a code is consumed by its first exchange');
  const second = await flow('read');
  const goodCode = second.back.searchParams.get('code');
  const tokenRes = await form(as.token_endpoint, {
    grant_type: 'authorization_code',
    code: goodCode,
    client_id: client.client_id,
    redirect_uri: CALLBACK,
    code_verifier: second.p.verifier,
  });
  assert.equal(tokenRes.status, 200);
  const tokens = await tokenRes.json();
  assert.equal(tokens.token_type, 'Bearer');
  assert.equal(tokens.scope, 'read');
  const replay = await form(as.token_endpoint, {
    grant_type: 'authorization_code',
    code: goodCode,
    client_id: client.client_id,
    redirect_uri: CALLBACK,
    code_verifier: second.p.verifier,
  });
  assert.equal((await replay.json()).error, 'invalid_grant');
  console.log('PASS token: wrong code, wrong verifier, single-use code, read scope');

  // 6. 用 OAuth 令牌调 MCP：只读不能写
  const listed = await (await rpc(tokens.access_token, 'tools/list')).json();
  assert.ok(listed.result.tools.some((t) => t.name === 'get_overview'));
  assert.ok(!listed.result.tools.some((t) => t.name === 'create_subscription'));
  const overview = await (await rpc(tokens.access_token, 'tools/call', { name: 'get_overview', arguments: {} })).json();
  assert.equal(overview.result.structuredContent.subscription_count, 0);
  const write = await (await rpc(tokens.access_token, 'tools/call', { name: 'create_subscription', arguments: { name: 'X', dry_run: true } })).json();
  assert.equal(write.result.isError, true);

  // 7. 刷新：轮换，旧的两个令牌都失效
  const refreshed = await form(as.token_endpoint, { grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: client.client_id });
  assert.equal(refreshed.status, 200);
  const next = await refreshed.json();
  assert.notEqual(next.access_token, tokens.access_token);
  assert.equal((await rpc(tokens.access_token, 'tools/list')).status, 401);
  assert.equal((await rpc(next.access_token, 'tools/list')).status, 200);
  const reuse = await form(as.token_endpoint, { grant_type: 'refresh_token', refresh_token: tokens.refresh_token });
  assert.equal((await reuse.json()).error, 'invalid_grant');
  console.log('PASS MCP with OAuth: read-only scope, refresh rotation, old tokens rejected');

  // 8. 后台列表、AI 开关、吊销
  const list = await (await get('/api/mcp/tokens', owner)).json();
  const grant = list.find((x) => x.kind === 'oauth');
  assert.equal(grant.name, 'Fictional Claude');
  assert.equal(grant.scope, 'read');
  assert.equal(list.filter((x) => x.kind === 'oauth').length, 1);
  const put = (body) => fetch(`${base}/api/settings`, { method: 'PUT', headers: { 'content-type': 'application/json', ...owner }, body: JSON.stringify(body) });
  assert.equal((await put({ aiEnabled: false })).status, 200);
  assert.equal((await rpc(next.access_token, 'tools/list')).status, 403);
  assert.equal((await put({ aiEnabled: true })).status, 200);
  assert.equal((await fetch(`${base}/api/mcp/tokens/${grant.id}`, { method: 'DELETE', headers: owner })).status, 200);
  assert.equal((await rpc(next.access_token, 'tools/list')).status, 401);
  assert.equal((await form(as.token_endpoint, { grant_type: 'refresh_token', refresh_token: next.refresh_token })).status, 400);
  console.log('PASS management: listed with client name, AI switch blocks, revoke kills access and refresh');

  // 9. 读写授权与 RFC 7009 吊销
  const w = await flow('write');
  const wt = await (
    await form(as.token_endpoint, {
      grant_type: 'authorization_code',
      code: w.back.searchParams.get('code'),
      client_id: client.client_id,
      redirect_uri: CALLBACK,
      code_verifier: w.p.verifier,
    })
  ).json();
  assert.equal(wt.scope, 'write');
  const writeTools = (await (await rpc(wt.access_token, 'tools/list')).json()).result.tools;
  assert.ok(writeTools.some((t) => t.name === 'create_subscription'));
  assert.equal((await form(as.revocation_endpoint, { token: wt.refresh_token })).status, 200);
  assert.equal((await rpc(wt.access_token, 'tools/list')).status, 401);
  console.log('PASS write scope lists write tools; RFC 7009 revocation');

  // 10. 原有的 MCP 令牌照常可用
  const legacy = await (
    await fetch(`${base}/api/mcp/tokens`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...owner },
      body: JSON.stringify({ name: 'Fictional', scope: 'read' }),
    })
  ).json();
  assert.equal((await rpc(legacy.token, 'tools/list')).status, 200);
  console.log('PASS existing bearer tokens unchanged');
}

const temp = await mkdtemp(join(tmpdir(), 'calends-oauth-release-'));
let worker;
try {
  const port = await freePort();
  await writeFile(
    join(temp, 'wrangler.json'),
    JSON.stringify({
      name: 'calends-oauth-release',
      main: resolve(root, 'worker/index.ts'),
      compatibility_date: '2026-10-01',
      compatibility_flags: ['nodejs_compat'],
      d1_databases: [{ binding: 'DB', database_name: 'fictional-oauth', database_id: '00000000-0000-0000-0000-000000000000' }],
      vars: { SETUP_TOKEN: SETUP },
    }),
  );
  worker = spawn(
    resolve(root, 'node_modules/.bin/wrangler'),
    [
      'dev',
      '--config',
      join(temp, 'wrangler.json'),
      '--local',
      '--ip',
      '127.0.0.1',
      '--port',
      String(port),
      '--persist-to',
      join(temp, 'data'),
      '--show-interactive-dev-session=false',
      '--log-level',
      'error',
    ],
    { cwd: temp, stdio: 'ignore', env: { ...process.env, CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV: 'false', WRANGLER_SEND_METRICS: 'false' } },
  );
  const base = `http://127.0.0.1:${port}`;
  let ready = false;
  for (let n = 0; n < 120; n++) {
    if (worker.exitCode !== null) throw new Error('Isolated Worker exited during startup');
    try {
      ready = (await fetch(`${base}/api/auth/status`)).ok;
    } catch {}
    if (ready) break;
    await new Promise((r) => setTimeout(r, 250));
  }
  assert.ok(ready, 'Worker startup timed out');
  await run(base);
} catch (e) {
  // Never print tokens, cookies or the setup secret.
  console.error(e instanceof Error ? e.message : 'OAuth release check failed');
  process.exitCode = 1;
} finally {
  if (worker && worker.exitCode === null) {
    worker.kill('SIGTERM');
    await new Promise((r) => worker.once('exit', r));
  }
  await rm(temp, { recursive: true, force: true });
}
