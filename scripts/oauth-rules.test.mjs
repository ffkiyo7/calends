import assert from 'node:assert/strict';
import { test } from 'node:test';
import { pkceMatches, redirectMatches, s256, validChallenge, validRedirect, validVerifier, withParams } from '../worker/ai/oauth-rules.ts';

test('PKCE S256 与 RFC 7636 附录 B 的示例一致', async () => {
  const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
  const challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
  assert.equal(await s256(verifier), challenge);
  assert.ok(validChallenge(challenge));
  assert.ok(await pkceMatches(verifier, challenge));
  assert.ok(!(await pkceMatches(`${verifier.slice(0, -1)}Y`, challenge)));
});

test('code_verifier 长度和字符受限', () => {
  assert.ok(validVerifier('a'.repeat(43)));
  assert.ok(validVerifier('a'.repeat(128)));
  assert.ok(!validVerifier('a'.repeat(42)));
  assert.ok(!validVerifier('a'.repeat(129)));
  assert.ok(!validVerifier(`${'a'.repeat(42)}+`));
  assert.ok(!validVerifier(undefined));
  assert.ok(!validChallenge('short'));
});

test('回调地址：https、本机回环 http、私有协议可以登记，危险协议和 #片段不行', () => {
  assert.ok(validRedirect('https://claude.ai/api/mcp/auth_callback'));
  assert.ok(validRedirect('http://localhost:33418/callback'));
  assert.ok(validRedirect('http://127.0.0.1/callback'));
  assert.ok(validRedirect('cursor://anysphere.cursor-mcp/oauth/callback'));
  assert.ok(!validRedirect('http://example.com/callback'));
  assert.ok(!validRedirect('https://claude.ai/cb#x'));
  for (const bad of ['javascript:alert(1)', 'data:text/html,x', 'file:///etc/passwd', '', 'not a url', 42]) assert.ok(!validRedirect(bad));
});

test('回调地址必须完全一致；只有本机回环可以换端口', () => {
  const claude = 'https://claude.ai/api/mcp/auth_callback';
  assert.ok(redirectMatches(claude, claude));
  assert.ok(!redirectMatches(claude, `${claude}/`));
  assert.ok(!redirectMatches(claude, 'https://evil.example/api/mcp/auth_callback'));
  assert.ok(redirectMatches('http://localhost/callback', 'http://localhost:51234/callback'));
  assert.ok(redirectMatches('http://127.0.0.1:1/callback', 'http://127.0.0.1:2/callback'));
  assert.ok(!redirectMatches('http://localhost/callback', 'http://127.0.0.1:51234/callback'));
  assert.ok(!redirectMatches('http://localhost/callback', 'http://localhost:51234/other'));
  assert.ok(!redirectMatches('https://a.example:1/cb', 'https://a.example:2/cb'));
});

test('回调参数追加在原有查询串之后', () => {
  assert.equal(withParams('https://a.example/cb?x=1', { code: 'c', state: undefined }), 'https://a.example/cb?x=1&code=c');
  assert.equal(withParams('https://a.example/cb', { error: 'access_denied', state: 's p' }), 'https://a.example/cb?error=access_denied&state=s+p');
});
