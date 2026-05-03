import { describe, it, expect } from 'vitest';
import { isOriginAllowed, isMutatingMethod } from '../src/index.js';

// 简易 Request mock：headers.get + url
function makeReq(url, originHeader) {
  return {
    url,
    headers: {
      get(name) {
        if (name.toLowerCase() === 'origin') return originHeader ?? null;
        return null;
      },
    },
  };
}

// ================================
// isMutatingMethod
// ================================

describe('isMutatingMethod', () => {
  it('returns false for safe methods', () => {
    expect(isMutatingMethod('GET')).toBe(false);
    expect(isMutatingMethod('HEAD')).toBe(false);
    expect(isMutatingMethod('OPTIONS')).toBe(false);
  });

  it('returns true for mutating methods', () => {
    expect(isMutatingMethod('POST')).toBe(true);
    expect(isMutatingMethod('PUT')).toBe(true);
    expect(isMutatingMethod('DELETE')).toBe(true);
    expect(isMutatingMethod('PATCH')).toBe(true);
  });
});

// ================================
// isOriginAllowed — CSRF 软防御
// ================================

describe('isOriginAllowed', () => {
  it('allows same-origin requests', () => {
    expect(isOriginAllowed(makeReq(
      'https://example.com/api/domains',
      'https://example.com'
    ))).toBe(true);
  });

  it('allows when path differs but origin matches', () => {
    expect(isOriginAllowed(makeReq(
      'https://example.com/api/foo/bar',
      'https://example.com'
    ))).toBe(true);
  });

  it('rejects cross-origin requests', () => {
    expect(isOriginAllowed(makeReq(
      'https://example.com/api/domains',
      'https://evil.com'
    ))).toBe(false);
  });

  it('rejects scheme mismatch (http vs https on same host)', () => {
    expect(isOriginAllowed(makeReq(
      'https://example.com/api/x',
      'http://example.com'
    ))).toBe(false);
  });

  it('rejects port mismatch', () => {
    expect(isOriginAllowed(makeReq(
      'https://example.com/api/x',
      'https://example.com:8443'
    ))).toBe(false);
  });

  it('rejects subdomain (origin is exact-match)', () => {
    expect(isOriginAllowed(makeReq(
      'https://example.com/api/x',
      'https://evil.example.com'
    ))).toBe(false);
  });

  // ---------- 关键设计决策：没有 Origin 头时放行 ----------

  it('allows requests with NO Origin header (curl / non-browser clients)', () => {
    expect(isOriginAllowed(makeReq('https://example.com/api/x', null))).toBe(true);
    expect(isOriginAllowed(makeReq('https://example.com/api/x', undefined))).toBe(true);
  });

  // ---------- 攻击向量 ----------

  it('rejects "null" origin (sandboxed iframe / data: URL attacks)', () => {
    expect(isOriginAllowed(makeReq(
      'https://example.com/api/x',
      'null'
    ))).toBe(false);
  });

  it('rejects malformed origin string', () => {
    expect(isOriginAllowed(makeReq(
      'https://example.com/api/x',
      'not-a-valid-url'
    ))).toBe(false);
  });

  it('rejects origin with extra path/query (defense against parser tricks)', () => {
    // new URL('https://example.com/path').origin === 'https://example.com'
    // 不过 Origin header 规范要求只有 scheme://host[:port]
    // 我们用 .origin 比较，所以即使有路径也只比较 origin 部分
    expect(isOriginAllowed(makeReq(
      'https://example.com/api/x',
      'https://example.com/path'
    ))).toBe(true);
    // 但跨站的带路径仍被拒
    expect(isOriginAllowed(makeReq(
      'https://example.com/api/x',
      'https://evil.com/path'
    ))).toBe(false);
  });

  it('localhost:port (wrangler dev) same-origin works', () => {
    expect(isOriginAllowed(makeReq(
      'http://localhost:8788/api/domains',
      'http://localhost:8788'
    ))).toBe(true);
    expect(isOriginAllowed(makeReq(
      'http://localhost:8788/api/domains',
      'http://localhost:8789'
    ))).toBe(false);
  });
});

// ================================
// 集成场景：模拟攻击者 evil.com 跨站发请求
// ================================

describe('integration: cross-site CSRF attack scenarios', () => {
  it('attacker form on evil.com → POST /api/domains/<id> DELETE → blocked', () => {
    // 浏览器会带上目标站的 cookie，但 Origin 头是 evil.com
    const attackerReq = makeReq(
      'https://yoursite.com/api/domains/abc',
      'https://evil.com'
    );
    expect(isMutatingMethod('DELETE')).toBe(true);
    expect(isOriginAllowed(attackerReq)).toBe(false);
    // 调用方应该返回 403
  });

  it('legitimate dashboard fetch from same site works', () => {
    const legitReq = makeReq(
      'https://yoursite.com/api/domains',
      'https://yoursite.com'
    );
    expect(isOriginAllowed(legitReq)).toBe(true);
  });

  it('curl / wrangler tail / Postman without Origin → allowed (admin tooling)', () => {
    const cliReq = makeReq('https://yoursite.com/api/domains', null);
    expect(isOriginAllowed(cliReq)).toBe(true);
  });
});
