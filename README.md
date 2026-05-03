# 🌍 Domain-Autocheck

<details>
    <summary>更新日志</summary>
    2025-12-14  
    1. 系统设置新增默认展开卡片、进度条、卡片布局设置  
    2. 新增亮色和暗色主题切换  
    3. 新增 `pp.ua`、`qzz.io`、`dpdns.org`、`xx.kg`、`us.kg`、`eu.cc` 6 个二级域名自动查询（自动填写注册厂商、注册日期、到期日期、续期链接，默认续期周期 1 年）  
    4. 列表新增分类下拉框过滤，添加域名增加注册账号属性  
</details>

> 现在除了一级域名配合 apikey 查询之外，新增 `pp.ua`、`qzz.io`、`dpdns.org`、`xx.kg`、`us.kg`、`eu.cc` 这 6 个二级域名时，点击查询后如果不需要填写注册账号和备注，其他信息都会自动填写，可以直接保存。

## ✨一句话介绍
部署在 Cloudflare Workers 的轻量级域名到期监控系统，支持 Telegram 通知与自动 WHOIS 填充。

## 🚀项目亮点
* Cloudflare Workers 部署，零服务器运维
* Cloudflare KV 持久化存储
* 支持 Telegram 到期提醒
* 支持一级域名 WHOIS 自动查询（需 WHOISJSON API）
* 支持指定二级域名自动查询：`pp.ua`、`us.kg`、`xx.kg`、`qzz.io`、`dpdns.org`、`eu.cc`

## ✅二级域名自动查询
支持以下二级域名自动识别注册商、注册日期、到期日期、续期链接，并默认续期周期 1 年：

| 二级域名 | 注册网址 |
|:---------|:---------|
| `pp.ua` | https://nic.ua |
| `us.kg` | https://domain.digitalplat.org |
| `xx.kg` | https://domain.digitalplat.org |
| `qzz.io` | https://domain.digitalplat.org |
| `dpdns.org` | https://domain.digitalplat.org |
| `eu.cc` | https://www.gname.com |

## 📌项目说明
本项目主要是和 AI 沟通创作而成，小伙伴可自行进行完善或魔改。

## 🎯适用场景
* 主要监控域名的到期情况
* 适合白嫖域名或需要定期续期的域名（如 `dpdns.org` 等）

## 🧩主要功能
* 日期监控
* 价格记录
* 注册商记录
* 自定义标签
* 自定义续费链接
* Telegram 提前通知

## 💻界面展示
暗色与亮色主题示例：

| 暗色主题 | 亮色主题 |
|:--:|:--:|
| ![暗色主题](https://github.com/user-attachments/assets/1f683ac4-6380-4201-b3a9-f4de9d5ed4b9) | ![亮色主题](https://github.com/user-attachments/assets/f6436078-8a0e-4a93-95e7-4d62e0865838) |

## 📌显示逻辑
### 卡头标签显示逻辑
| 判定条件         | 标签状态   |
|:-----------------|:-----------|
| 剩余天数小于1天  | ❌已过期    |
| 剩余天数为1-20天 | 📢即将过期 |
| 剩余天数大于20天 | ✅正常      |

### 卡片进度条显示逻辑
| 判定条件                  | 进度条状态 |
|:--------------------------|:-----------|
| 剩余天数小于周期的10%     | 🔴已过期   |
| 剩余天数是周期的10%-30%   | 🟡即将过期 |
| 剩余天数大于等于周期的30% | 🟢正常     |

## 🚀部署流程
1. 创建 `Workers` 服务，粘贴代码
2. 创建一个 `KV` 命名空间（名字可自定义）
3. 绑定 `KV`，变量名称：`DOMAIN_MONITOR`（注意大写）
4. 绑定自定义域名（可选）
5. 配置环境变量（见下表）
6. 配置定时通知（`Cron` 触发器）

> Cloudflare `Cron` 使用 UTC 时间，与北京时间相差 8 小时。  
> 例如设置为 00:00，则北京时间 08:00 进行通知。

## ⚙️环境变量
> 优先级：Cloudflare 环境变量 > 代码中的变量 > 默认值

| 名称              | 示例                                                                           | 必填 | 备注                                     |
|:------------------|:-------------------------------------------------------------------------------|:----:|:-----------------------------------------|
| TOKEN             | 默认是 `domain`                                                                |  ✅️  | 登录密码，建议自定义，不填则默认 `domain` |
| TG_TOKEN          | Telegram 找 [@BotFather](https://t.me/BotFather) 获取                           |  ❌️  | 可在界面后端配置                         |
| TG_ID             | Telegram 找 [@userinfobot](https://t.me/userinfobot) 获取，或群机器人也可       |  ❌️  | 可在界面后端配置                         |
| SITE_NAME         | 默认为域名到期监控                                                             |  ❌️  | 不填则默认“域名到期监控”                 |
| LOGO_URL          | https://123abc.com/logo.svg                                                    |  ❌️  | 网站 logo，有需要可自行设置             |
| BACKGROUND_URL    | https://123abc.com/img.jpg                                                     |  ❌️  | 背景图，有需要可自行设置                 |
| WHOISJSON_API_KEY | 去 [WHOISJSON](https://whoisjson.com/) 免费注册获取 API，每月免费 1000 次查询 |  ❌️  | 仅支持一级域名的自动查询                 |

## ♻️代码更新方式
功能基本稳定，通常只有一些体验类小修复，并不影响整体使用。  
如需更新，只要重新复制粘贴代码即可；域名数据存储在 `KV` 中，保持 `KV` 不变不会丢失数据。  
> 🚨如果你在代码中手动填写了变量，更新前请先备份这些值。

## ⭐ Star 星星走起
![Star History](https://api.star-history.com/svg?repos=jy02739244/Domain-AutoCheck&type=Date)
