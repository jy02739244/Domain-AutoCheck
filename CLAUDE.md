# Domain-AutoCheck

## 技术栈

- 运行时: Cloudflare Workers (ES Module)
- 语言: 原生 JavaScript (ES2020+)
- 存储: Cloudflare KV (绑定名: `DOMAIN_MONITOR`)
- 测试: Vitest（普通 Node 环境，通过 `vitest.config.js` 把 `cloudflare:sockets` 别名到本地 mock）
- 前端: Bootstrap 5.3 + 原生 JS，全部内嵌在单个 HTML 模板中
- 外部 API: WhoisJSON API、whois.pp.ua、Gname WHOIS/RDAP（eu.cc）、DigitalPlat WHOIS/RDAP

## 部署约束（重要）

**`src/index.js` 必须保持单文件可部署**——用户工作流是直接复制文件内容到 Cloudflare Dashboard 的 Worker 编辑器粘贴部署。
所有工具函数（escape / 鉴权 / sanitize 等）都内嵌在 `src/index.js` 顶部，并通过 `export` 暴露给 vitest 测试 import。
**不要把代码拆到独立文件再 import**，会破坏粘贴部署。

## 项目结构

- `src/index.js` — 唯一源码文件（约 7700+ 行，包含后端逻辑、安全工具、前端 HTML 模板）
- `test/auth.spec.js` — 鉴权工具单元测试（40 用例）
- `test/escape.spec.js` — HTML/URL 转义测试（32 用例）
- `test/sanitize.spec.js` — 类型收窄测试（23 用例）
- `test/ratelimit.spec.js` — 登录频次限制测试（14 用例）
- `test/csrf.spec.js` — CSRF Origin 校验测试（16 用例）
- `test/cloudflare-sockets-mock.js` — 测试用的 `cloudflare:sockets` mock
- `vitest.config.js` — vitest 配置（alias mock）
- `wrangler.toml` — Cloudflare Workers 配置
- `package.json` — 依赖和脚本

## src/index.js 主要代码段

| 行号范围 | 内容 |
|----------|------|
| 1-26 | 导入 + 环境变量注入 |
| 28-77 | 配置常量 + 基础工具函数（formatDate / jsonResponse） |
| 80-126 | **HTML / URL 转义**（`escapeHtml` / `escapeHtmlBackend` / `safeUrl`），均 `export` |
| 128-249 | **鉴权工具**（HMAC 签名 cookie + 恒定时间比较），主要函数均 `export`<br>· `signSession` / `verifySession` / `readCookie` / `buildSessionCookie` |
| 245-256 | `getCorrectPassword()` — 默认密码兜底时打 console.warn |
| 258-283 | `getWhoisQueryFunction()` — 域名查询路由 |
| 286-332 | `queryDomainWhois()` — 一级域名查询（WhoisJSON API） |
| 335-419 | `queryPpUaWhois()` — pp.ua 域名查询（TCP socket，超时 10 秒） |
| 422-590 | `queryEuCcWhois()` — eu.cc 域名查询（RDAP 优先 + TCP WHOIS 兜底，超时 30 秒） |
| 594-764 | `queryDigitalPlatWhois()` — DigitalPlat 域名查询（RDAP + TCP 兜底） |
| 773-5646 | HTML 模板（含前端 inline JS，前端 escape/safeUrl 在 line ~3115） |
| 5653+ | `handleRequest()` 请求路由（鉴权入口） |
| 5798+ | `handleApiRequest()` API 处理 |
| 6114+ | **类型收窄**（`sanitizeRenewCycle` / `sanitizePrice`），均 `export` |

## 安全工具一览（均位于 `src/index.js` 顶部）

| 导出 | 作用 |
|------|------|
| `escapeHtml(value)` | 完整 5 字符 HTML 转义，浏览器 DOM 防御 |
| `escapeHtmlBackend(value)` | Telegram parse_mode=HTML 专用（只转 < > &） |
| `safeUrl(value)` | URL 协议白名单（http/https/mailto），其余返回 `''` |
| `timingSafeEqualStr(a, b)` | 字符串恒定时间比较 |
| `hmacSha256Hex(secret, msg)` | HMAC-SHA256 hex（带 importKey 缓存） |
| `signSession(token, ttl?)` | 签发 session cookie：`<exp>.<nonce>.<sig>` |
| `verifySession(token, cookie)` | 校验 session cookie（过期 + 签名） |
| `readCookie(header, name)` | 从 Cookie 头解析单个 cookie 值 |
| `buildSessionCookie(value, request, ttl?)` | 构造 Set-Cookie，HTTPS 自动加 Secure |
| `buildClearSessionCookie(request)` | 构造清除 cookie 的 Set-Cookie |
| `sanitizeRenewCycle(input)` | 续期周期类型收窄（防 XSS 注入） |
| `sanitizePrice(input)` | 价格类型收窄（防 XSS 注入） |
| `getClientIp(request)` | 提取客户端 IP（CF-Connecting-IP / X-Forwarded-For / X-Real-IP） |
| `getLoginFailCount(kv, ip)` / `recordLoginFail(kv, ip)` / `clearLoginFail(kv, ip)` | 登录失败计数（KV 里 15 分钟窗口） |
| `isOriginAllowed(request)` | CSRF 软防御：Origin 与请求 URL origin 是否同源 |
| `isMutatingMethod(method)` | 判断请求方法是否需要 CSRF 检查（非 GET/HEAD/OPTIONS） |
| `_getMaxLoginFails()` / `_getLoginFailWindowSeconds()` | 测试辅助 getter（绕过 Workers `export const` 限制） |

⚠️ 前端 dashboard / setup 页面因为 inline 在 HTML 字符串里无法 import，
在模板内 inline 了 `escapeHtml` / `safeUrl` / `_setupEscapeHtml` 的等价实现。
**修改顶部 export 版本时必须同步前端 inline**（搜索 `keep in sync`）。

⚠️ **inline 在反引号 HTML 模板里的正则字面量**（如 `domainRegex` / `safeUrl` 的 `^https?://`），
由于 JS template literal 会把 `\X`（X 为非转义字符）还原成 `X`，**必须把 `\X` 写成 `\\X`**，
否则 `\.` 变成 `.`、`\/` 变成 `/`，导致正则失效甚至 SyntaxError。
搜索 inline 处的注释 `template literal 会吃掉单个反斜杠`。

## 安全机制

- **鉴权**：HMAC-SHA256 签名 cookie（密钥就是环境变量 `TOKEN`），过期 24h。修改 TOKEN 即可让所有 session 失效。
- **登录频次限制**：同一 IP 在 15 分钟窗口内最多失败 5 次，超过返回 429（KV 存计数，最终一致性）。
- **CSRF 软防御**：`/api/*` 的 mutating 请求（POST/PUT/DELETE/PATCH）若带 Origin 头必须同源；没有 Origin 头放行（兼容 curl/Postman）。配合 cookie 的 `SameSite=Strict` 已挡住浏览器 CSRF。
- **XSS 防御**：所有 user 输入字段在拼进 innerHTML 前用 `escapeHtml`；`<a href>` 用 `safeUrl` 协议白名单（只放行 http/https/mailto）。后端再用 `sanitizeRenewCycle` / `sanitizePrice` 做类型收窄做深度防御。
- **密码恒定时间比较**：用 `timingSafeEqualStr` 防时序攻击。

## 域名查询逻辑

### 路由函数 `getWhoisQueryFunction(domainName)`（line 258）

根据域名后缀分发到不同的查询函数：

- `.pp.ua` → `queryPpUaWhois`（TCP socket 直连 whois.pp.ua:43，超时 10 秒）
- `.eu.cc` → `queryEuCcWhois`（RDAP 优先 `rdap.gname.com` + TCP WHOIS 兜底 `whois.gname.com:43`，超时 30 秒）
- `.qzz.io` / `.dpdns.org` / `.us.kg` / `.xx.kg` → `queryDigitalPlatWhois`（RDAP + TCP 兜底）
- 一级域名（1个点）且有 API Key → `queryDomainWhois`（WhoisJSON API）
- 其他 → 返回 null（不支持）

### 域名验证逻辑（出现两处，需同步修改）

1. **后端验证**: `handleApiRequest` 中的 `/api/whois` 路由（在 `handleApiRequest` 内部，搜索 `domainRegex`）
2. **前端验证**: HTML 模板中的添加域名表单验证（在前端 inline script，搜索 `domainRegex`）

验证规则：
- 正则: `/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/`
- 点数: 一级域名允许 1 个点，二级域名（pp.ua / eu.cc / DigitalPlat）允许 2 个点
- 新增二级域名后缀时，需要在两处验证逻辑中都添加 `isXxx` 变量

### 注册商自动填充

添加域名时根据后缀自动填充注册商和续费链接（搜索 `nic.ua/en/my/domains`），新增后缀时需要在此处添加。

## 环境变量

- `DOMAIN_MONITOR` — KV 命名空间绑定（必需）
- `TOKEN` — 登录密码（默认: `"domain"`，**生产环境必须设置**，否则 HMAC 密钥裸奔）
- `TG_TOKEN` / `TG_ID` — Telegram 通知配置（可选）
- `WHOISJSON_API_KEY` — WhoisJSON API 密钥（可选，用于一级域名查询）
- `SITE_NAME` / `LOGO_URL` / `BACKGROUND_URL` — 自定义外观（可选）

## API 路由

- `GET /api/domains` — 列出所有域名
- `POST /api/domains` — 添加域名
- `PUT /api/domains/:id` — 更新域名
- `DELETE /api/domains/:id` — 删除域名
- `POST /api/whois` — WHOIS 查询
- `GET /api/telegram/config` — 获取 Telegram 配置
- `POST /api/telegram/config` — 保存 Telegram 配置
- `POST /api/telegram/test` — 测试 Telegram 消息

## 新增域名后缀的修改清单

添加新的二级域名后缀支持时，需要修改以下位置：

1. `getWhoisQueryFunction()` — 添加后缀匹配条件
2. 后端域名验证 — 添加 `isXxx` 变量和点数判断
3. 前端域名验证 — 同上，保持同步
4. 注册商自动填充 — 添加注册商和续费链接
5. 如果需要新的查询方式，创建新的查询函数

## 测试与部署

```bash
npm test            # vitest 全套（95 用例）
npx wrangler deploy --dry-run  # 验证打包成功
npm run deploy      # 真实部署
```

如需手动复制部署：直接拷 `src/index.js` 全文到 Cloudflare Dashboard Worker 编辑器即可。
