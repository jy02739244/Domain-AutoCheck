import { describe, it, expect, beforeEach } from 'vitest';
import {
  timingSafeEqualStr,
  hmacSha256Hex,
  signSession,
  verifySession,
  readCookie,
  buildSessionCookie,
  buildClearSessionCookie,
  _getSessionCookieName,
  _getSessionTtlSeconds,
  _resetHmacKeyCache,
} from '../src/index.js';

const SESSION_COOKIE_NAME = _getSessionCookieName();
const SESSION_TTL_SECONDS = _getSessionTtlSeconds();

beforeEach(() => {
  _resetHmacKeyCache();
});

// ================================
// timingSafeEqualStr
// ================================

describe('timingSafeEqualStr', () => {
  it('returns true for equal strings', () => {
    expect(timingSafeEqualStr('abc', 'abc')).toBe(true);
    expect(timingSafeEqualStr('', '')).toBe(true);
    expect(timingSafeEqualStr('hello world', 'hello world')).toBe(true);
  });

  it('returns false for different strings of same length', () => {
    expect(timingSafeEqualStr('abc', 'abd')).toBe(false);
    expect(timingSafeEqualStr('aaa', 'aab')).toBe(false);
  });

  it('returns false for different lengths', () => {
    expect(timingSafeEqualStr('abc', 'abcd')).toBe(false);
    expect(timingSafeEqualStr('abc', 'ab')).toBe(false);
    expect(timingSafeEqualStr('', 'a')).toBe(false);
  });

  it('returns false for non-string inputs', () => {
    expect(timingSafeEqualStr(null, 'abc')).toBe(false);
    expect(timingSafeEqualStr('abc', undefined)).toBe(false);
    expect(timingSafeEqualStr(123, '123')).toBe(false);
    expect(timingSafeEqualStr({}, 'abc')).toBe(false);
    expect(timingSafeEqualStr(undefined, undefined)).toBe(false);
  });
});

// ================================
// hmacSha256Hex
// ================================

describe('hmacSha256Hex', () => {
  it('produces a 64-char lowercase hex digest', async () => {
    const sig = await hmacSha256Hex('secret', 'message');
    expect(sig).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is deterministic for same inputs', async () => {
    const a = await hmacSha256Hex('secret', 'message');
    const b = await hmacSha256Hex('secret', 'message');
    expect(a).toBe(b);
  });

  // RFC 4231 / known HMAC-SHA256 test vector
  it('matches known vector: HMAC-SHA256("key", "The quick brown fox jumps over the lazy dog")', async () => {
    const sig = await hmacSha256Hex('key', 'The quick brown fox jumps over the lazy dog');
    expect(sig).toBe('f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8');
  });

  it('different secrets yield different signatures', async () => {
    const a = await hmacSha256Hex('k1', 'msg');
    const b = await hmacSha256Hex('k2', 'msg');
    expect(a).not.toBe(b);
  });

  it('different messages yield different signatures', async () => {
    const a = await hmacSha256Hex('k', 'msg1');
    const b = await hmacSha256Hex('k', 'msg2');
    expect(a).not.toBe(b);
  });

  it('importKey cache returns consistent results across many calls', async () => {
    // Hits the cache hot path
    const results = await Promise.all(
      Array.from({ length: 10 }, () => hmacSha256Hex('cached-secret', 'same-msg'))
    );
    expect(new Set(results).size).toBe(1);
  });
});

// ================================
// signSession + verifySession
// ================================

describe('signSession + verifySession', () => {
  const TOKEN = 'mySecret123';

  it('round-trips successfully', async () => {
    const cookie = await signSession(TOKEN);
    expect(await verifySession(TOKEN, cookie)).toBe(true);
  });

  it('cookie format is <exp>.<nonce>.<sig>', async () => {
    const cookie = await signSession(TOKEN);
    const parts = cookie.split('.');
    expect(parts).toHaveLength(3);
    expect(Number(parts[0])).toBeGreaterThan(Math.floor(Date.now() / 1000));
    expect(parts[1]).toMatch(/^[0-9a-f]{32}$/);
    expect(parts[2]).toMatch(/^[0-9a-f]{64}$/);
  });

  it('two consecutive signs produce different cookies (different nonces)', async () => {
    const a = await signSession(TOKEN);
    const b = await signSession(TOKEN);
    expect(a).not.toBe(b);
    // But both must verify
    expect(await verifySession(TOKEN, a)).toBe(true);
    expect(await verifySession(TOKEN, b)).toBe(true);
  });

  it('respects custom ttl', async () => {
    const cookie = await signSession(TOKEN, 60);
    const exp = Number(cookie.split('.')[0]);
    const now = Math.floor(Date.now() / 1000);
    expect(exp).toBeGreaterThanOrEqual(now + 59);
    expect(exp).toBeLessThanOrEqual(now + 61);
  });

  // ---------- attack vectors ----------

  it('rejects legacy "auth=true" attack', async () => {
    expect(await verifySession(TOKEN, 'true')).toBe(false);
    expect(await verifySession(TOKEN, 'auth=true')).toBe(false);
  });

  it('rejects with wrong token', async () => {
    const cookie = await signSession(TOKEN);
    expect(await verifySession('wrong-token', cookie)).toBe(false);
  });

  it('rejects tampered signature', async () => {
    const cookie = await signSession(TOKEN);
    const tampered = cookie.slice(0, -2) + (cookie.endsWith('aa') ? 'bb' : 'aa');
    expect(await verifySession(TOKEN, tampered)).toBe(false);
  });

  it('rejects tampered exp (attempt to extend session)', async () => {
    const cookie = await signSession(TOKEN);
    const [exp, nonce, sig] = cookie.split('.');
    const newExp = String(Number(exp) + 100000);
    expect(await verifySession(TOKEN, `${newExp}.${nonce}.${sig}`)).toBe(false);
  });

  it('rejects tampered nonce', async () => {
    const cookie = await signSession(TOKEN);
    const [exp, nonce, sig] = cookie.split('.');
    const tampered = `${exp}.${'0'.repeat(nonce.length)}.${sig}`;
    expect(await verifySession(TOKEN, tampered)).toBe(false);
  });

  it('rejects expired session', async () => {
    // Sign with negative TTL → already expired
    const cookie = await signSession(TOKEN, -10);
    expect(await verifySession(TOKEN, cookie)).toBe(false);
  });

  it('rejects empty/null/undefined cookie value', async () => {
    expect(await verifySession(TOKEN, '')).toBe(false);
    expect(await verifySession(TOKEN, null)).toBe(false);
    expect(await verifySession(TOKEN, undefined)).toBe(false);
  });

  it('rejects empty/null/undefined token (defense-in-depth)', async () => {
    const cookie = await signSession(TOKEN);
    expect(await verifySession('', cookie)).toBe(false);
    expect(await verifySession(null, cookie)).toBe(false);
    expect(await verifySession(undefined, cookie)).toBe(false);
  });

  it('rejects malformed cookie (wrong segment count)', async () => {
    expect(await verifySession(TOKEN, 'a.b')).toBe(false);
    expect(await verifySession(TOKEN, 'a.b.c.d')).toBe(false);
    expect(await verifySession(TOKEN, 'just-a-string')).toBe(false);
    expect(await verifySession(TOKEN, '')).toBe(false);
  });

  it('rejects cookie with non-numeric exp', async () => {
    const sig = await hmacSha256Hex(TOKEN, 'abc.0123456789abcdef0123456789abcdef');
    expect(
      await verifySession(TOKEN, `abc.0123456789abcdef0123456789abcdef.${sig}`)
    ).toBe(false);
  });

  it('rejects cookie with too-short nonce', async () => {
    const exp = Math.floor(Date.now() / 1000) + 100;
    const shortNonce = 'short';
    const sig = await hmacSha256Hex(TOKEN, `${exp}.${shortNonce}`);
    expect(await verifySession(TOKEN, `${exp}.${shortNonce}.${sig}`)).toBe(false);
  });

  it('invalidates ALL sessions when token rotates', async () => {
    const cookie = await signSession('token-v1');
    expect(await verifySession('token-v1', cookie)).toBe(true);
    expect(await verifySession('token-v2', cookie)).toBe(false);
  });
});

// ================================
// readCookie
// ================================

describe('readCookie', () => {
  it('returns null for empty / null header', () => {
    expect(readCookie('', 'session')).toBe(null);
    expect(readCookie(null, 'session')).toBe(null);
    expect(readCookie(undefined, 'session')).toBe(null);
  });

  it('reads single cookie', () => {
    expect(readCookie('session=abc', 'session')).toBe('abc');
  });

  it('reads cookie among many', () => {
    expect(readCookie('a=1; session=abc; b=2', 'session')).toBe('abc');
    expect(readCookie('a=1;session=abc;b=2', 'session')).toBe('abc');
    expect(readCookie('  a=1 ;  session=abc  ;  b=2  ', 'session')).toBe('abc');
  });

  it('handles values containing "="', () => {
    expect(readCookie('a=foo=bar', 'a')).toBe('foo=bar');
  });

  it('returns null when cookie name not found', () => {
    expect(readCookie('a=1; b=2', 'session')).toBe(null);
  });

  it('does not match partial cookie names (prefix attack)', () => {
    expect(readCookie('mysession=abc', 'session')).toBe(null);
    expect(readCookie('session_extra=abc', 'session')).toBe(null);
  });

  it('handles malformed cookie segments without "="', () => {
    expect(readCookie('garbage; session=abc', 'session')).toBe('abc');
  });
});

// ================================
// buildSessionCookie / buildClearSessionCookie
// ================================

describe('buildSessionCookie / buildClearSessionCookie', () => {
  const httpsReq = { url: 'https://example.com/login' };
  const httpReq = { url: 'http://localhost:8787/login' };

  it('builds Set-Cookie with all required attributes', () => {
    const c = buildSessionCookie('token-value', httpsReq);
    expect(c).toContain(`${SESSION_COOKIE_NAME}=token-value`);
    expect(c).toContain('Path=/');
    expect(c).toContain('HttpOnly');
    expect(c).toContain('SameSite=Strict');
    expect(c).toContain(`Max-Age=${SESSION_TTL_SECONDS}`);
    expect(c).toContain('Secure');
  });

  it('omits Secure on http (local dev)', () => {
    const c = buildSessionCookie('token-value', httpReq);
    expect(c).not.toContain('Secure');
    expect(c).toContain(`${SESSION_COOKIE_NAME}=token-value`);
    expect(c).toContain('HttpOnly');
    expect(c).toContain('SameSite=Strict');
  });

  it('respects custom ttl', () => {
    const c = buildSessionCookie('v', httpsReq, 3600);
    expect(c).toContain('Max-Age=3600');
  });

  it('clear cookie has Max-Age=0 and empty value', () => {
    const c = buildClearSessionCookie(httpsReq);
    expect(c).toContain(`${SESSION_COOKIE_NAME}=;`);
    expect(c).toContain('Max-Age=0');
    expect(c).toContain('Secure');
    expect(c).toContain('HttpOnly');
    expect(c).toContain('SameSite=Strict');
  });

  it('clear cookie omits Secure on http', () => {
    const c = buildClearSessionCookie(httpReq);
    expect(c).not.toContain('Secure');
    expect(c).toContain('Max-Age=0');
  });
});

// ================================
// 集成场景：完整登录 / 登出 / 重放流程
// ================================

describe('end-to-end auth flow', () => {
  const TOKEN = 'integration-secret';
  const httpsReq = { url: 'https://example.com/dashboard' };

  it('login → set cookie → verify → logout → reject', async () => {
    // 登录：服务端签发 cookie
    const sessionValue = await signSession(TOKEN);
    const setCookie = buildSessionCookie(sessionValue, httpsReq);

    // 客户端把 Set-Cookie 的值放回 Cookie 头里发回来
    const cookieHeader = `${SESSION_COOKIE_NAME}=${sessionValue}; other=foo`;
    const parsed = readCookie(cookieHeader, SESSION_COOKIE_NAME);
    expect(parsed).toBe(sessionValue);

    // 验证通过
    expect(await verifySession(TOKEN, parsed)).toBe(true);

    // 登出后：服务端清除 cookie，新请求不再带 session
    const clearCookie = buildClearSessionCookie(httpsReq);
    expect(clearCookie).toContain('Max-Age=0');

    // 模拟登出后请求：cookie 头里没有 session
    const afterLogout = readCookie('other=foo', SESSION_COOKIE_NAME);
    expect(afterLogout).toBe(null);
    expect(await verifySession(TOKEN, afterLogout)).toBe(false);
  });

  it('Set-Cookie value can be parsed back by readCookie', async () => {
    const sessionValue = await signSession(TOKEN);
    const setCookie = buildSessionCookie(sessionValue, httpsReq);

    // Set-Cookie: session=<value>; Path=/; ...
    // 浏览器只回送 name=value 部分，模拟一下
    const sentByBrowser = setCookie.split(';')[0];
    const parsed = readCookie(sentByBrowser, SESSION_COOKIE_NAME);
    expect(parsed).toBe(sessionValue);
    expect(await verifySession(TOKEN, parsed)).toBe(true);
  });
});
