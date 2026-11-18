// OAuth 的纯规则：PKCE 校验、回调地址校验与匹配。不依赖 Worker 环境，测试直接导入。

/** RFC 7636：code_verifier 为 43–128 个非保留字符 */
export const validVerifier = (v: unknown): v is string => typeof v === 'string' && /^[A-Za-z0-9\-._~]{43,128}$/.test(v);

/** S256 的 code_challenge 是 43 个 base64url 字符（SHA-256 去掉填充） */
export const validChallenge = (v: unknown): v is string => typeof v === 'string' && /^[A-Za-z0-9\-_]{43}$/.test(v);

const b64url = (b: Uint8Array) =>
  btoa(String.fromCharCode(...b))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

export async function s256(verifier: string): Promise<string> {
  return b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))));
}

/** 校验 verifier 与授权时登记的 challenge 是否对得上 */
export async function pkceMatches(verifier: unknown, challenge: string): Promise<boolean> {
  return validVerifier(verifier) && (await s256(verifier)) === challenge;
}

const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);
/** 不允许作为回调的协议：能在浏览器里执行脚本或读本地文件 */
const UNSAFE_SCHEMES = new Set(['javascript:', 'data:', 'file:', 'vbscript:', 'about:', 'blob:']);

function parse(uri: unknown): URL | undefined {
  if (typeof uri !== 'string' || !uri || uri.length > 2000) return undefined;
  try {
    return new URL(uri);
  } catch {
    return undefined;
  }
}

const isLoopback = (u: URL) => u.protocol === 'http:' && LOOPBACK.has(u.hostname);

/**
 * 客户端注册时可登记的回调地址（RFC 8252 / OAuth 2.1）：
 * https 网址、本机回环 http（命令行客户端用临时端口），或桌面应用的私有协议。不允许带 #片段。
 */
export function validRedirect(uri: unknown): boolean {
  const u = parse(uri);
  if (!u || u.hash || UNSAFE_SCHEMES.has(u.protocol)) return false;
  if (u.protocol === 'https:') return !!u.hostname;
  if (u.protocol === 'http:') return isLoopback(u);
  return /^[a-z][a-z0-9+.-]*:$/.test(u.protocol);
}

/** 授权请求的回调地址必须与登记的完全一致；本机回环地址按 RFC 8252 忽略端口 */
export function redirectMatches(registered: string, given: string): boolean {
  if (registered === given) return true;
  const a = parse(registered);
  const b = parse(given);
  if (!a || !b || !isLoopback(a) || !isLoopback(b)) return false;
  return a.hostname === b.hostname && a.pathname === b.pathname && a.search === b.search;
}

/** 在回调地址上追加参数，保留它原有的查询串 */
export function withParams(uri: string, params: Record<string, string | undefined>): string {
  const u = new URL(uri);
  for (const [k, v] of Object.entries(params)) if (v !== undefined) u.searchParams.set(k, v);
  return u.toString();
}
