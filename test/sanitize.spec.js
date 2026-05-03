import { describe, it, expect } from 'vitest';
import { sanitizeRenewCycle, sanitizePrice } from '../src/index.js';

// ================================
// sanitizeRenewCycle
// ================================

describe('sanitizeRenewCycle', () => {
  it('accepts valid input', () => {
    expect(sanitizeRenewCycle({ value: 1, unit: 'year' })).toEqual({ value: 1, unit: 'year' });
    expect(sanitizeRenewCycle({ value: 30, unit: 'day' })).toEqual({ value: 30, unit: 'day' });
    expect(sanitizeRenewCycle({ value: 12, unit: 'month' })).toEqual({ value: 12, unit: 'month' });
  });

  it('coerces numeric string to number', () => {
    expect(sanitizeRenewCycle({ value: '5', unit: 'year' })).toEqual({ value: 5, unit: 'year' });
  });

  // ---------- attack vectors ----------

  it('rejects malicious string in value field (the original XSS)', () => {
    expect(sanitizeRenewCycle({ value: '<script>alert(1)</script>', unit: 'year' })).toBe(null);
    expect(sanitizeRenewCycle({ value: '<img src=x onerror=alert(1)>', unit: 'year' })).toBe(null);
  });

  it('rejects NaN / Infinity / -Infinity', () => {
    expect(sanitizeRenewCycle({ value: NaN, unit: 'year' })).toBe(null);
    expect(sanitizeRenewCycle({ value: Infinity, unit: 'year' })).toBe(null);
    expect(sanitizeRenewCycle({ value: -Infinity, unit: 'year' })).toBe(null);
  });

  it('rejects zero / negative / over-limit values', () => {
    expect(sanitizeRenewCycle({ value: 0, unit: 'year' })).toBe(null);
    expect(sanitizeRenewCycle({ value: -1, unit: 'year' })).toBe(null);
    expect(sanitizeRenewCycle({ value: 10000, unit: 'year' })).toBe(null);
    expect(sanitizeRenewCycle({ value: 9999, unit: 'year' })).toEqual({ value: 9999, unit: 'year' });
  });

  it('forces unsupported unit to "year"', () => {
    expect(sanitizeRenewCycle({ value: 1, unit: 'evil' })).toEqual({ value: 1, unit: 'year' });
    expect(sanitizeRenewCycle({ value: 1, unit: '<script>' })).toEqual({ value: 1, unit: 'year' });
    expect(sanitizeRenewCycle({ value: 1, unit: 'YEAR' })).toEqual({ value: 1, unit: 'year' });
    expect(sanitizeRenewCycle({ value: 1, unit: undefined })).toEqual({ value: 1, unit: 'year' });
  });

  it('returns null for non-object input', () => {
    expect(sanitizeRenewCycle(null)).toBe(null);
    expect(sanitizeRenewCycle(undefined)).toBe(null);
    expect(sanitizeRenewCycle('not an object')).toBe(null);
    expect(sanitizeRenewCycle(123)).toBe(null);
    expect(sanitizeRenewCycle(true)).toBe(null);
  });

  it('arrays return null (typeof "object" but not valid)', () => {
    // Defensive: although `typeof [] === 'object'`, an array.value is undefined → coerced NaN → rejected
    expect(sanitizeRenewCycle([1, 'year'])).toBe(null);
  });

  it('output never carries extra keys (prototype pollution / trash data)', () => {
    const malicious = { value: 1, unit: 'year', __proto__: { evil: true }, extra: '<script>' };
    const result = sanitizeRenewCycle(malicious);
    expect(Object.keys(result).sort()).toEqual(['unit', 'value']);
  });
});

// ================================
// sanitizePrice
// ================================

describe('sanitizePrice', () => {
  it('accepts valid input', () => {
    expect(sanitizePrice({ value: 100, currency: '¥', unit: 'year' }))
      .toEqual({ value: 100, currency: '¥', unit: 'year' });
    expect(sanitizePrice({ value: 0, currency: '$', unit: 'month' }))
      .toEqual({ value: 0, currency: '$', unit: 'month' });
  });

  it('coerces numeric string to number', () => {
    expect(sanitizePrice({ value: '99.5', currency: '$', unit: 'year' }))
      .toEqual({ value: 99.5, currency: '$', unit: 'year' });
  });

  it('preserves null / undefined for "do not update" semantics', () => {
    // updateDomain 依赖：当 caller 传 null/undefined 时不修改现有数据
    expect(sanitizePrice(null)).toBe(null);
    expect(sanitizePrice(undefined)).toBe(undefined);
  });

  it('treats empty value as "未填价格"', () => {
    expect(sanitizePrice({ value: '', currency: '¥', unit: 'year' }))
      .toEqual({ value: '', currency: '', unit: 'year' });
    expect(sanitizePrice({ value: null, currency: '¥', unit: 'year' }))
      .toEqual({ value: '', currency: '', unit: 'year' });
    expect(sanitizePrice({ value: undefined, currency: '¥', unit: 'year' }))
      .toEqual({ value: '', currency: '', unit: 'year' });
  });

  // ---------- attack vectors ----------

  it('rejects malicious string in value field', () => {
    expect(sanitizePrice({ value: '<script>alert(1)</script>', currency: '$', unit: 'year' }))
      .toBe(null);
  });

  it('rejects NaN / Infinity / negative', () => {
    expect(sanitizePrice({ value: NaN, currency: '$', unit: 'year' })).toBe(null);
    expect(sanitizePrice({ value: Infinity, currency: '$', unit: 'year' })).toBe(null);
    expect(sanitizePrice({ value: -1, currency: '$', unit: 'year' })).toBe(null);
  });

  it('strips dangerous HTML chars from currency (XSS depth defense)', () => {
    expect(sanitizePrice({ value: 1, currency: '<$>', unit: 'year' }).currency).toBe('$');
    expect(sanitizePrice({ value: 1, currency: '"\'&', unit: 'year' }).currency).toBe('');
    expect(sanitizePrice({ value: 1, currency: '<script>$</script>', unit: 'year' }).currency)
      .toBe('scrip'); // 5 字符截断后是 'scrip'（剔除 < > / 后剩 'script$/script'，slice(0,5)）
  });

  it('truncates currency to 5 chars max', () => {
    expect(sanitizePrice({ value: 1, currency: 'ABCDEFG', unit: 'year' }).currency).toHaveLength(5);
    expect(sanitizePrice({ value: 1, currency: 'ABCDEFG', unit: 'year' }).currency).toBe('ABCDE');
  });

  it('handles non-string currency', () => {
    expect(sanitizePrice({ value: 1, currency: 123, unit: 'year' }).currency).toBe('');
    expect(sanitizePrice({ value: 1, currency: null, unit: 'year' }).currency).toBe('');
    expect(sanitizePrice({ value: 1, currency: undefined, unit: 'year' }).currency).toBe('');
  });

  it('forces unsupported unit to "year"', () => {
    expect(sanitizePrice({ value: 1, currency: '$', unit: 'forever' }).unit).toBe('year');
    expect(sanitizePrice({ value: 1, currency: '$', unit: '<script>' }).unit).toBe('year');
  });

  it('returns null for non-object input', () => {
    expect(sanitizePrice('not an object')).toBe(null);
    expect(sanitizePrice(123)).toBe(null);
    expect(sanitizePrice(true)).toBe(null);
  });

  it('output never carries extra keys', () => {
    const malicious = { value: 1, currency: '$', unit: 'year', evil: '<script>', __proto__: {} };
    const result = sanitizePrice(malicious);
    expect(Object.keys(result).sort()).toEqual(['currency', 'unit', 'value']);
  });
});

// ================================
// 集成场景：模拟攻击者直接 PUT API 注入恶意 renewCycle / price
// ================================

describe('integration: malicious API payload', () => {
  it('attacker PUT with XSS in renewCycle.value gets sanitized to null', () => {
    const attackerPayload = {
      name: 'a.com',
      registrationDate: '2025-01-01',
      expiryDate: '2026-01-01',
      renewCycle: { value: '<img src=x onerror=alert(document.cookie)>', unit: 'year' },
    };
    const sanitized = sanitizeRenewCycle(attackerPayload.renewCycle);
    expect(sanitized).toBe(null);
    // 写入 KV 的将是 null，前端渲染回退到 '1 年' 文本
  });

  it('attacker PUT with currency containing script tag is stripped', () => {
    const attackerPayload = {
      price: { value: 99, currency: '<script>x</script>', unit: 'year' },
    };
    const sanitized = sanitizePrice(attackerPayload.price);
    expect(sanitized.currency).not.toContain('<');
    expect(sanitized.currency).not.toContain('>');
    expect(sanitized.currency.length).toBeLessThanOrEqual(5);
  });
});
