import { describe, it, expect } from 'vitest';
import { escapeHtml, escapeHtmlBackend, safeUrl } from '../src/index.js';

// ================================
// escapeHtml — 完整 5 字符 HTML 转义（用于浏览器 DOM 注入防护）
// ================================

describe('escapeHtml', () => {
  it('escapes the five special characters', () => {
    expect(escapeHtml('& < > " \'')).toBe('&amp; &lt; &gt; &quot; &#39;');
  });

  it('blocks common XSS payloads', () => {
    expect(escapeHtml('<script>alert(1)</script>'))
      .toBe('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(escapeHtml('<img src=x onerror=alert(1)>'))
      .toBe('&lt;img src=x onerror=alert(1)&gt;');
  });

  it('blocks attribute breakout via double quote', () => {
    expect(escapeHtml('" onmouseover="alert(1)'))
      .toBe('&quot; onmouseover=&quot;alert(1)');
  });

  it('blocks attribute breakout via single quote', () => {
    expect(escapeHtml("' onmouseover='alert(1)"))
      .toBe('&#39; onmouseover=&#39;alert(1)');
  });

  it('returns empty string for null / undefined', () => {
    expect(escapeHtml(null)).toBe('');
    expect(escapeHtml(undefined)).toBe('');
  });

  it('coerces numbers and booleans to string', () => {
    expect(escapeHtml(42)).toBe('42');
    expect(escapeHtml(true)).toBe('true');
    expect(escapeHtml(0)).toBe('0');
  });

  it('passes through ASCII / unicode unchanged', () => {
    expect(escapeHtml('example.com')).toBe('example.com');
    expect(escapeHtml('域名监控 🌍')).toBe('域名监控 🌍');
  });

  it('always escapes & to &amp;, even if input looks pre-encoded (consistent behavior)', () => {
    // 函数无脑转义，不"智能识别"已转义内容；这是 OWASP 推荐的一致性行为
    expect(escapeHtml('&amp;')).toBe('&amp;amp;');
  });
});

// ================================
// escapeHtmlBackend — Telegram parse_mode=HTML（只转 < > &，保留引号）
// ================================

describe('escapeHtmlBackend', () => {
  it('escapes only < > &', () => {
    expect(escapeHtmlBackend('a < b > c & d'))
      .toBe('a &lt; b &gt; c &amp; d');
  });

  it('preserves quotes (Telegram allows them in plain text)', () => {
    expect(escapeHtmlBackend('she said "hi" and \'bye\''))
      .toBe('she said "hi" and \'bye\'');
  });

  it('blocks tag injection that would break Telegram message', () => {
    expect(escapeHtmlBackend('<script>x</script>'))
      .toBe('&lt;script&gt;x&lt;/script&gt;');
  });

  it('returns empty string for null / undefined', () => {
    expect(escapeHtmlBackend(null)).toBe('');
    expect(escapeHtmlBackend(undefined)).toBe('');
  });

  it('coerces numbers to string', () => {
    expect(escapeHtmlBackend(123)).toBe('123');
  });
});

// ================================
// safeUrl — 协议白名单
// ================================

describe('safeUrl', () => {
  it('allows http://', () => {
    expect(safeUrl('http://example.com/path')).toBe('http://example.com/path');
  });

  it('allows https://', () => {
    expect(safeUrl('https://example.com/path?q=1')).toBe('https://example.com/path?q=1');
  });

  it('allows uppercase HTTPS://', () => {
    expect(safeUrl('HTTPS://example.com')).toBe('HTTPS://example.com');
  });

  it('allows mailto:', () => {
    expect(safeUrl('mailto:foo@bar.com')).toBe('mailto:foo@bar.com');
  });

  // ---------- attack vectors ----------

  it('blocks javascript:', () => {
    expect(safeUrl('javascript:alert(1)')).toBe('');
  });

  it('blocks JaVaScRiPt: (case-insensitive bypass)', () => {
    expect(safeUrl('JaVaScRiPt:alert(1)')).toBe('');
  });

  it('blocks javascript: with leading whitespace', () => {
    expect(safeUrl('  javascript:alert(1)')).toBe('');
    expect(safeUrl('\tjavascript:alert(1)')).toBe('');
    expect(safeUrl('\njavascript:alert(1)')).toBe('');
  });

  it('blocks data: URLs', () => {
    expect(safeUrl('data:text/html,<script>alert(1)</script>')).toBe('');
    expect(safeUrl('data:image/svg+xml;base64,...')).toBe('');
  });

  it('blocks vbscript:', () => {
    expect(safeUrl('vbscript:msgbox(1)')).toBe('');
  });

  it('blocks file://', () => {
    expect(safeUrl('file:///etc/passwd')).toBe('');
  });

  it('blocks protocol-relative URLs (//cdn.evil)', () => {
    expect(safeUrl('//cdn.evil.com/x')).toBe('');
  });

  it('blocks relative paths', () => {
    expect(safeUrl('/admin')).toBe('');
    expect(safeUrl('../etc')).toBe('');
    expect(safeUrl('admin')).toBe('');
  });

  it('returns empty string for empty / null / undefined', () => {
    expect(safeUrl('')).toBe('');
    expect(safeUrl('   ')).toBe('');
    expect(safeUrl(null)).toBe('');
    expect(safeUrl(undefined)).toBe('');
  });

  it('returns empty string (NOT "#") to let UI render disabled state', () => {
    // 防回归：safeUrl 之前返回 '#' 会导致 disabled 按钮渲染逻辑失效
    expect(safeUrl('javascript:alert(1)')).toBe('');
    expect(safeUrl('javascript:alert(1)')).not.toBe('#');
  });

  it('rejects URLs longer than 2048 chars (DoS guard)', () => {
    const long = 'https://example.com/' + 'a'.repeat(3000);
    expect(safeUrl(long)).toBe('');
    // 边界：刚好 2048 应通过
    const ok = 'https://e.co/' + 'a'.repeat(2048 - 'https://e.co/'.length);
    expect(ok.length).toBe(2048);
    expect(safeUrl(ok)).toBe(ok);
    // 2049 字符应被拒
    expect(safeUrl(ok + 'x')).toBe('');
  });
});

// ================================
// 集成攻击场景：domain card 渲染时遭受攻击
// ================================

describe('integration: domain card under attack', () => {
  it('XSS payload in domain.name is rendered as literal text', () => {
    const malicious = '<script>alert("pwned")</script>';
    const rendered = '<h5>' + escapeHtml(malicious) + '</h5>';
    expect(rendered).toBe('<h5>&lt;script&gt;alert(&quot;pwned&quot;)&lt;/script&gt;</h5>');
    expect(rendered).not.toContain('<script>');
  });

  it('javascript: in renewLink is reduced to empty (button rendered disabled by caller)', () => {
    const malicious = 'javascript:fetch("/api/domains",{method:"DELETE"})';
    const safeRenewLink = safeUrl(malicious);
    expect(safeRenewLink).toBe('');
    // 调用方根据空字符串渲染禁用按钮
    const html = safeRenewLink
      ? '<a href="' + escapeHtml(safeRenewLink) + '">链接</a>'
      : '<button disabled>链接</button>';
    expect(html).toBe('<button disabled>链接</button>');
  });

  it('legitimate https renewLink renders <a> with safe href', () => {
    const url = 'https://example.com/renew?id=42';
    const safe = safeUrl(url);
    expect(safe).toBe(url);
    const html = '<a href="' + escapeHtml(safe) + '">go</a>';
    expect(html).toBe('<a href="https://example.com/renew?id=42">go</a>');
  });

  it('Telegram message: malicious < and > are neutralized', () => {
    const malicious = 'evil.com<img src=x>';
    const tgMsg = '🌍 域名: ' + escapeHtmlBackend(malicious) + '\n';
    expect(tgMsg).toBe('🌍 域名: evil.com&lt;img src=x&gt;\n');
    // Telegram API 不会把它当成标签拒绝消息，且渲染为字面文本
  });
});
