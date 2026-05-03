# Domain-AutoCheck

## 技术栈

- 运行时: Cloudflare Workers (ES Module)
- 语言: 原生 JavaScript (ES2020+)
- 存储: Cloudflare KV (绑定名: `DOMAIN_MONITOR`)
- 测试: Vitest + `@cloudflare/vitest-pool-workers`
- 前端: Bootstrap 5.3 + 原生 JS，全部内嵌在单个 HTML 模板中
- 外部 API: WhoisJSON API、NIC.UA WHOIS、DigitalPlat WHOIS/RDAP

## 项目结构

- `src/index.js` — 主文件（约 7000+ 行，包含后端逻辑 + 前端 HTML 模板）
- `test/index.spec.js` — 测试文件
- `wrangler.toml` — Cloudflare Workers 配置
- `package.json` — 依赖和脚本

## src/index.js 主要代码段

| 行号范围 | 内容 |
|----------|------|
| 28-52 | 配置常量（图标、默认值等） |
| 58-73 | 工具函数 |
| 76-97 | `getWhoisQueryFunction()` — 域名查询路由，根据后缀选择查询函数 |
| 100-147 | `queryDomainWhois()` — 一级域名查询（WhoisJSON API） |
| 149-234 | `queryPpUaWhois()` — pp.ua 域名查询（TCP socket 连 whois.pp.ua:43） |
| 236-406 | `queryDigitalPlatWhois()` — DigitalPlat 域名查询（RDAP 优先 + TCP WHOIS 兜底） |
| 413-5242 | HTML 模板（含前端 JS） |
| 5252+ | `handleRequest()` 请求路由 + API 处理 |

## 域名查询逻辑

### 路由函数 `getWhoisQueryFunction(domainName)` (line 76)

根据域名后缀分发到不同的查询函数：

- `.pp.ua` → `queryPpUaWhois` (TCP socket 直连 whois.pp.ua:43)
- `.eu.cc` → `queryEuCcWhois` (TCP socket 直连 whois.gname.com:43)
- `.qzz.io` / `.dpdns.org` / `.us.kg` / `.xx.kg` → `queryDigitalPlatWhois` (RDAP + TCP 兜底)
- 一级域名（1个点）且有 API Key → `queryDomainWhois` (WhoisJSON API)
- 其他 → 返回 null（不支持）

### 域名验证逻辑（出现两处，需同步修改）

1. **后端验证**: `handleApiRequest` 中的 `/api/whois` 路由（约 line 5560）
2. **前端验证**: HTML 模板中的添加域名表单验证（约 line 2907）

验证规则：
- 正则: `/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/`
- 点数: 一级域名允许 1 个点，二级域名（pp.ua / DigitalPlat）允许 2 个点
- 新增二级域名后缀时，需要在两处验证逻辑中都添加

### 注册商自动填充（约 line 5030）

添加域名时根据后缀自动填充注册商和续费链接，新增后缀时需要在此处添加对应信息。

## 环境变量

- `DOMAIN_MONITOR` — KV 命名空间绑定（必需）
- `TOKEN` — 登录密码（默认: `"domain"`）
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

1. `getWhoisQueryFunction()` (line ~85) — 添加后缀匹配条件
2. 后端域名验证 (line ~5570) — 添加 `isXxx` 变量和点数判断
3. 前端域名验证 (line ~2917) — 同上，保持同步
4. 注册商自动填充 (line ~5030) — 添加注册商和续费链接
5. 如果需要新的查询方式，创建新的查询函数
