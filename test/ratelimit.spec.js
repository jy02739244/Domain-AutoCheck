import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  getClientIp,
  getLoginFailCount,
  recordLoginFail,
  clearLoginFail,
  _getMaxLoginFails,
  _getLoginFailWindowSeconds,
  _resetKvUnavailableWarn,
} from '../src/index.js';

const MAX_LOGIN_FAILS = _getMaxLoginFails();
const LOGIN_FAIL_WINDOW_SECONDS = _getLoginFailWindowSeconds();

// 简易内存 KV mock：模拟 Cloudflare KV 的 get / put / delete + 可选 expirationTtl
function makeMockKv() {
  const store = new Map();
  const calls = { puts: [], deletes: [] };
  return {
    async get(key) {
      const e = store.get(key);
      if (!e) return null;
      if (e.expiresAt && e.expiresAt < Date.now()) {
        store.delete(key);
        return null;
      }
      return e.value;
    },
    async put(key, value, opts = {}) {
      calls.puts.push({ key, value, opts });
      const expiresAt = opts.expirationTtl ? Date.now() + opts.expirationTtl * 1000 : null;
      store.set(key, { value, expiresAt });
    },
    async delete(key) {
      calls.deletes.push(key);
      store.delete(key);
    },
    _store: store,
    _calls: calls,
  };
}

// ================================
// getClientIp
// ================================

describe('getClientIp', () => {
  function makeReq(headers) {
    return {
      headers: {
        get(name) {
          // 大小写不敏感模拟
          for (const [k, v] of Object.entries(headers)) {
            if (k.toLowerCase() === name.toLowerCase()) return v;
          }
          return null;
        },
      },
    };
  }

  it('reads CF-Connecting-IP first', () => {
    expect(getClientIp(makeReq({ 'CF-Connecting-IP': '1.2.3.4' }))).toBe('1.2.3.4');
  });

  it('falls back to X-Forwarded-For (first hop)', () => {
    expect(getClientIp(makeReq({ 'X-Forwarded-For': '5.6.7.8, 9.9.9.9' }))).toBe('5.6.7.8');
  });

  it('falls back to X-Real-IP', () => {
    expect(getClientIp(makeReq({ 'X-Real-IP': '10.0.0.1' }))).toBe('10.0.0.1');
  });

  it('returns "unknown" when no header present', () => {
    expect(getClientIp(makeReq({}))).toBe('unknown');
  });

  it('CF-Connecting-IP takes precedence over X-Forwarded-For', () => {
    expect(getClientIp(makeReq({
      'CF-Connecting-IP': '1.1.1.1',
      'X-Forwarded-For': '2.2.2.2',
    }))).toBe('1.1.1.1');
  });

  // ---------- 防御性 trim：不同代理可能在头里前后带空格 ----------

  it('trims whitespace from CF-Connecting-IP', () => {
    expect(getClientIp(makeReq({ 'CF-Connecting-IP': '  1.2.3.4  ' }))).toBe('1.2.3.4');
    expect(getClientIp(makeReq({ 'CF-Connecting-IP': '\t1.2.3.4\n' }))).toBe('1.2.3.4');
  });

  it('trims whitespace from X-Real-IP', () => {
    expect(getClientIp(makeReq({ 'X-Real-IP': '  10.0.0.1  ' }))).toBe('10.0.0.1');
  });

  it('treats whitespace-only header as empty (falls through)', () => {
    expect(getClientIp(makeReq({
      'CF-Connecting-IP': '   ',  // 只有空格，trim 后空字符串
      'X-Real-IP': '5.6.7.8',
    }))).toBe('5.6.7.8');
  });
});

// ================================
// getLoginFailCount / recordLoginFail / clearLoginFail
// ================================

describe('login fail counter', () => {
  let kv;
  beforeEach(() => { kv = makeMockKv(); });

  it('returns 0 for unknown IP', async () => {
    expect(await getLoginFailCount(kv, '1.1.1.1')).toBe(0);
  });

  it('returns 0 if KV is null/undefined (graceful degrade)', async () => {
    _resetKvUnavailableWarn();
    const spy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    expect(await getLoginFailCount(null, '1.1.1.1')).toBe(0);
    expect(await getLoginFailCount(undefined, '1.1.1.1')).toBe(0);
    spy.mockRestore();
  });

  it('recordLoginFail increments count and sets TTL', async () => {
    expect(await recordLoginFail(kv, '1.1.1.1')).toBe(1);
    expect(await recordLoginFail(kv, '1.1.1.1')).toBe(2);
    expect(await recordLoginFail(kv, '1.1.1.1')).toBe(3);
    expect(await getLoginFailCount(kv, '1.1.1.1')).toBe(3);

    // 校验每次 put 都设了正确的 TTL
    for (const call of kv._calls.puts) {
      expect(call.opts.expirationTtl).toBe(LOGIN_FAIL_WINDOW_SECONDS);
    }
  });

  it('separate IPs have independent counters', async () => {
    await recordLoginFail(kv, '1.1.1.1');
    await recordLoginFail(kv, '1.1.1.1');
    await recordLoginFail(kv, '2.2.2.2');
    expect(await getLoginFailCount(kv, '1.1.1.1')).toBe(2);
    expect(await getLoginFailCount(kv, '2.2.2.2')).toBe(1);
    expect(await getLoginFailCount(kv, '3.3.3.3')).toBe(0);
  });

  it('clearLoginFail removes counter for specified IP only', async () => {
    await recordLoginFail(kv, '1.1.1.1');
    await recordLoginFail(kv, '2.2.2.2');
    await clearLoginFail(kv, '1.1.1.1');
    expect(await getLoginFailCount(kv, '1.1.1.1')).toBe(0);
    expect(await getLoginFailCount(kv, '2.2.2.2')).toBe(1);
  });

  it('clearLoginFail with null kv is no-op (no crash)', async () => {
    await expect(clearLoginFail(null, '1.1.1.1')).resolves.toBeUndefined();
  });

  it('uses the documented namespaced key prefix', async () => {
    await recordLoginFail(kv, '1.2.3.4');
    expect(kv._calls.puts[0].key).toBe('login:fail:1.2.3.4');
  });

  it('handles tampered KV value (non-numeric string) gracefully', async () => {
    await kv.put('login:fail:evil', '<script>alert(1)</script>');
    expect(await getLoginFailCount(kv, 'evil')).toBe(0);
  });

  it('threshold semantics: 5 fails should block (>=  MAX_LOGIN_FAILS)', async () => {
    for (let i = 0; i < MAX_LOGIN_FAILS; i++) await recordLoginFail(kv, '1.1.1.1');
    expect(await getLoginFailCount(kv, '1.1.1.1')).toBe(MAX_LOGIN_FAILS);
    // 第 6 次仍能 record，但调用方应该已经在 >=MAX 时拒绝
    expect(await recordLoginFail(kv, '1.1.1.1')).toBe(MAX_LOGIN_FAILS + 1);
  });

  // ---------- 'unknown' / loopback IP：本地 dev / 边缘异常时跳过限速，避免锁全员 ----------

  describe('local/unknown IP handling (skip rate-limit to avoid locking dev)', () => {
    const SKIP_IPS = [
      'unknown',
      'localhost',
      '0.0.0.0',
      // IPv4 loopback 整段 127.0.0.0/8
      '127.0.0.1',
      '127.0.0.2',
      '127.255.255.254',
      // IPv6 loopback：压缩 + 未压缩
      '::1',
      '0:0:0:0:0:0:0:1',
      // IPv4-mapped IPv6 loopback（大小写不敏感，含混合大小写）
      '::ffff:127.0.0.1',
      '::FFFF:127.0.0.5',  // 全大写
      '::FfFf:127.0.0.10', // 混合大小写
    ];

    it.each(SKIP_IPS)('getLoginFailCount returns 0 for %s without touching KV', async (ip) => {
      // 先种一个值，证明 KV 即使有数据也被绕过
      await kv.put('login:fail:' + ip, '99');
      expect(await getLoginFailCount(kv, ip)).toBe(0);
    });

    it.each(SKIP_IPS)('recordLoginFail does NOT increment for %s', async (ip) => {
      expect(await recordLoginFail(kv, ip)).toBe(0);
      expect(await recordLoginFail(kv, ip)).toBe(0);
      expect(kv._calls.puts.filter(c => c.key === 'login:fail:' + ip)).toHaveLength(0);
    });

    it.each(SKIP_IPS)('clearLoginFail is no-op for %s', async (ip) => {
      await clearLoginFail(kv, ip);
      expect(kv._calls.deletes.filter(k => k === 'login:fail:' + ip)).toHaveLength(0);
    });

    it('does not lock out other IPs when local IP is "spammed" (wrangler dev scenario)', async () => {
      // 模拟本地 dev：wrangler 设 cf-connecting-ip: 127.0.0.1，连续失败 100 次
      for (let i = 0; i < 100; i++) await recordLoginFail(kv, '127.0.0.1');
      // 真实公网 IP 仍然干净
      expect(await getLoginFailCount(kv, '203.0.113.42')).toBe(0);
    });

    it('public IPs are NOT skipped (production rate-limit still works)', async () => {
      // 防回归：确保只有 loopback / unknown 被跳过，公网 IP 必须计数
      // IPv4 公网
      expect(await recordLoginFail(kv, '203.0.113.42')).toBe(1);
      expect(await recordLoginFail(kv, '8.8.8.8')).toBe(1);
      expect(await recordLoginFail(kv, '1.1.1.1')).toBe(1);
      // IPv4 私网（非 loopback）也必须计数（Cloudflare 不会让私网进 CF-Connecting-IP，
      // 但万一某种部署里出现，也不能误跳）
      expect(await recordLoginFail(kv, '10.0.0.1')).toBe(1);
      expect(await recordLoginFail(kv, '192.168.1.1')).toBe(1);
      // IPv6 公网（防止 _shouldSkipRateLimit 被误改成 ip.includes(':') 之类）
      expect(await recordLoginFail(kv, '2001:db8::1')).toBe(1);
      expect(await recordLoginFail(kv, '2606:4700:4700::1111')).toBe(1); // Cloudflare DNS IPv6
      // 看似含 "127" 但不是 loopback：IPv4 含 127 的非 loopback
      expect(await recordLoginFail(kv, '128.127.0.1')).toBe(1);
      expect(await recordLoginFail(kv, '212.7.0.1')).toBe(1);
    });

    it('rejects strings that do not match IPv4 shape (字母 / 不完整段)', async () => {
      // 防御：如果 _shouldSkipRateLimit 用 startsWith('127.') 会误判这些
      // 严格 regex 只放行 4 段数字字面量
      expect(await recordLoginFail(kv, '127.evil.example.com')).toBe(1);
      expect(await recordLoginFail(kv, '127.x.y.z')).toBe(1);
      expect(await recordLoginFail(kv, '127.')).toBe(1);
      expect(await recordLoginFail(kv, '127')).toBe(1);   // 不带点根本不像 IP
      expect(await recordLoginFail(kv, '127.0.0')).toBe(1); // 段数不足
      expect(await recordLoginFail(kv, '127.0.0.1.2')).toBe(1); // 段数过多
    });

    it('accepts IPv4 shape even with out-of-range octets (acceptable in trust boundary)', async () => {
      // 已知行为：regex 不校验 octet 范围（0-255），所以 '127.999.999.999' 仍被当 loopback。
      // CF-Connecting-IP 永远是合法 IP，攻击者无法控制此头；
      // 严格 octet 校验需要复杂正则 (25[0-5]|2[0-4]\d|...)，过度工程化。
      // 这里记录此行为防止未来回归"修复"。
      expect(await recordLoginFail(kv, '127.999.999.999')).toBe(0); // 仍被跳过
    });

    it('rejects malformed IPv4-mapped IPv6 (strict regex)', async () => {
      expect(await recordLoginFail(kv, '::ffff:127.evil.x.y')).toBe(1);
      expect(await recordLoginFail(kv, '::ffff:127.')).toBe(1);
      expect(await recordLoginFail(kv, '::ffff:128.0.0.1')).toBe(1);  // mapped 但目标不是 loopback
    });
  });

  // ---------- KV 不可用时打 console.warn ----------

  describe('KV unavailable warning', () => {
    beforeEach(() => { _resetKvUnavailableWarn(); });

    it('warns once on first call when kv is null', async () => {
      const spy = vi.spyOn(console, 'warn').mockImplementation(() => {});
      await getLoginFailCount(null, '1.1.1.1');
      await getLoginFailCount(null, '2.2.2.2');
      await recordLoginFail(null, '3.3.3.3');
      // 只打一次（避免日志爆炸）
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.mock.calls[0][0]).toMatch(/KV 不可用/);
      spy.mockRestore();
    });

    it('does not warn when kv is provided (normal operation)', async () => {
      const spy = vi.spyOn(console, 'warn').mockImplementation(() => {});
      await getLoginFailCount(kv, '1.1.1.1');
      await recordLoginFail(kv, '1.1.1.1');
      await clearLoginFail(kv, '1.1.1.1');
      expect(spy).not.toHaveBeenCalled();
      spy.mockRestore();
    });
  });
});
