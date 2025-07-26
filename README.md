---
title: Domain-AutoCheck域名到期监控
cover: https://imgr2.952536.xyz/Hexo/Article/20250726232833566.png
swiper_index: 10
top_group_index: 10
background: '#fff'
date: 2025-07-26 13:29:27
updated:
tags:
  - 域名监控
  - 到期监控
categories:
  - 项目教程
keywords:
description:
top:
top_img:
comments:
toc:
toc_number:
toc_style_simple:
copyright:
copyright_author:
copyright_author_href:
copyright_url:
copyright_info: 此文章版权归Faiz所有，如有转载，请注明来自原作者
mathjax:
katex:
aplayer:
highlight_shrink:
aside:
ai:
  - 项目是部署在Cloudflare平台的，作用只有监控域名的到期情况。
  - 主要是针对那些白嫖的域名，例如`dpdns.org`之类的，可能有人注册了好几个，需要定期点击续期，或者有些白嫖的一年的域名，可以帮助进行到期监控，避免忘记到期时间。
  - 主要功能：日期监控、价格记录、注册商记录、自定义标签、自定义续费链接、telegram提前通知。
---





{% tip ban %}
  本项目主要是通过和Ai沟通创作而成，有能力者可自行进行完善或魔改
{% endtip %}

# 💻界面展示

<div align="center">
  
  <!-- 默认显示第一张图片 -->
  <img src="https://imgr2.952536.xyz/Hexo/Article/PixPin_2025-07-26_23-05-27.png" alt="图片1" style="max-width:100%;" id="currentImage">
  
  <!-- 图片导航 -->
  <div>
    <b>图片导航：</b>
    <a href="https://imgr2.952536.xyz/Hexo/Article/PixPin_2025-07-26_23-05-27.png" target="_blank">1</a> |
    <a href="https://imgr2.952536.xyz/Hexo/Article/PixPin_2025-07-26_23-03-45.png" target="_blank">2</a> |
    <a href="https://imgr2.952536.xyz/Hexo/Article/PixPin_2025-07-26_23-04-07.png" target="_blank">3</a> |
    <a href="https://imgr2.952536.xyz/Hexo/Article/PixPin_2025-07-26_23-05-42.png" target="_blank">4</a> |
    <a href="https://imgr2.952536.xyz/Hexo/Article/PixPin_2025-07-26_23-05-13.png" target="_blank">5</a> |
    <a href="https://imgr2.952536.xyz/Hexo/Article/20250726233245913.png" target="_blank">6</a>
  </div>
  
  <p><i>点击数字可在新标签页中查看对应图片</i></p>
</div>

---

### 图片链接

1. [图片1](https://imgr2.952536.xyz/Hexo/Article/PixPin_2025-07-26_23-05-27.png)
2. [图片2](https://imgr2.952536.xyz/Hexo/Article/PixPin_2025-07-26_23-03-45.png)
3. [图片3](https://imgr2.952536.xyz/Hexo/Article/PixPin_2025-07-26_23-04-07.png)
4. [图片4](https://imgr2.952536.xyz/Hexo/Article/PixPin_2025-07-26_23-05-42.png)
5. [图片5](https://imgr2.952536.xyz/Hexo/Article/PixPin_2025-07-26_23-05-13.png)
6. [图片6](https://imgr2.952536.xyz/Hexo/Article/20250726233245913.png)

------------------------------------------------------------------------------------------------------------------------

# 🚀部署流程

## 一、项目准备
1. Fork本项目，项目地址：https://github.com/kamanfaiz/CF-Domain-Autocheck
2. 因为cloudflare分配的项目网址容易被墙，所以最好准备一个域名：
   * 如果选择workers部署的话，要把域名解析到cloudflare上(最好不要是双向解析的域名，用起来麻烦)；
   * 如果选择pages部署的话，只要有一个支持`cname功能`的域名就可以了，解不解析都可以。

## 二、新建项目

### 1.wokers部署
* 来到[Cloudflare网站](https://www.cloudflare.com)，登录账户后点击左侧`计算机`，选择`Workers和Pages`，选择右上方的`创建`，选择`从 Hello World! 开始`，名字随便取，自己认得就行，然后点击`部署`
* 复制本项目的`_worker.js`代码粘贴进创建的wokers项目中，点击`部署`即可。

### 2.pages部署
* 先fork本项目到自己仓库(🙏顺便点个星星吧~)；
* 来到cloudflare创建项目——选择pages——点击`导入现有 Git 存储库`选项——连接自己的github仓库；
* 选择`CF-Domain-Autocheck`项目——点击`开始设置`——项目名称随便填，自己认得就行——点击`保存并部署`

访问项目网址，看到以下页面就表示已经成功部署了
![](https://imgr2.952536.xyz/Hexo/Article/PixPin_2025-07-26_23-09-11.png)

{% tip warning %}
  能看懂网页的小伙伴可以自行根据网页提示进行操作，如果有看不懂的，请接着往下看
{% endtip %}

## 三、KV创建（用于储存域名信息）
返回Cloudflare首页，点击左侧的`存储和数据库`，选择`KV`，点击右上角`Create Instance`，名字随便取自己认识就行，然后点击`创建`即可。
![](https://imgr2.952536.xyz/Hexo/Article/PixPin_2025-07-26_14-05-55.png)

## 四、为项目绑定KV
1. workers部署绑定KV方式:
   * 回到刚才部署的项目——点击`绑定`——选择`KV命名空间`——在弹出的页面中，按照如下填法填写：
   * 变量名称：{% label DOMAIN_MONITOR red %}，注意大写，怕填错就复制粘贴
   * KV命名空间：下拉菜单选择刚才创建的KV名字
   * 最后，点击绑定
   {% gallery %}
     ![](https://imgr2.952536.xyz/Hexo/Article/PixPin_2025-07-26_14-09-09.png)
     ![](https://imgr2.952536.xyz/Hexo/Article/PixPin_2025-07-26_14-12-15.png)
     ![](https://imgr2.952536.xyz/Hexo/Article/PixPin_2025-07-26_14-13-34.png)
   {% endgallery %}

2. pages部署绑定KV方式：
   * 选择`设置`——点击`绑定`——点击`添加`——选择`KV命名空间`
   * 按照图示填入内容，变量名称：{% label DOMAIN_MONITOR red %}，注意大写，怕填错就复制粘贴
   * KV命名空间：下拉菜单选择刚才创建的KV名字
   * 最后，点击绑定
   {% gallery %}
     ![](https://imgr2.952536.xyz/Hexo/Article/PixPin_2025-07-26_14-18-20.png)
     ![](https://imgr2.952536.xyz/Hexo/Article/PixPin_2025-07-26_14-21-17.png)
   {% endgallery %}

   {% tip warning %}
      用pages部署的小伙伴，一定要记得在绑定完KV命名空间之后，要重试部署
   {% endtip %}
   ![](https://imgr2.952536.xyz/Hexo/Article/20250726231646216.png)

通过上述方式绑定完KV之后，返回项目网址，点击`我已完成设置，刷新页面`，即可来到登录界面

## 五、添加环境变量
现在其实已经可以访问项目网址，进行访问了，默认密码是{% label domain red %}，变量修改如下：
{% tip ban %}
  用workers部署的既可以在代码中改变量，也可以选择在cloudflare的环境变量中单独添加
  用pages部署的只能在cloudflare的环境变量中单独添加，`且在配置完后一定要记得重试部署，才能生效`
{% endtip %}
1. 代码变量修改，只需要修改如下代码中的值就可以了：
```js
// 网站图标和背景图片，可在环境变量中设置
const DEFAULT_LOGO = 'https://imgr2.952536.xyz/Hexo/Article/domain-outline.png'; // 默认Logo图片，外置变量名为LOGO_URL
const DEFAULT_BACKGROUND = 'https://nzr2.952536.xyz/Cover/bujidao-street.png'; // 默认背景图片，外置变量名为BACKGROUND_URL

// 登录密码设置
const DEFAULT_TOKEN = ''; // 在此处设置默认密码，留空则使用'domain'，外置变量名为TOKEN

// Telegram通知配置
const DEFAULT_TG_TOKEN = ''; // 你的Telegram机器人Token，留空则尝试读取环境变量中TG_TOKEN的值
const DEFAULT_TG_ID = '';    // 你的Telegram聊天ID，留空则尝试读取环境变量中TG_ID的值

// 网站标题配置
const DEFAULT_SITE_NAME = ''; // 默认网站标题，外置环境变量名为SITE_NAME
```
2. cloudflare外置环境变量修改，具体变量名如下：

> <center> 📢 所有的变量优先级都是：Cloudflare环境变量＞代码中的变量＞默认值 </center>

| 名称           | 示例                                                                     | 必填 | 备注                                     |
|:---------------|:-------------------------------------------------------------------------|:----:|:-----------------------------------------|
| TOKEN          | 默认是domain                                                             |  ✅️   | 登录密码，最好自定义，不填则默认是domain |
| TG_TOKEN       | telegram找[@BotFather](https://t.me/BotFather)获取                       |  ❌️   | 可在网页端配置                           |
| TG_ID          | telegram找[@userinfobot](https://t.me/userinfobot)获取，或者群机器人也行 |  ❌️   | 可在网页端配置                           |
| SITE_NAME      | 域名到期监控/Domain AutoCheck                                            |  ❌️   | 默认就是域名到期监控                     |
| LOGO_URL       | https://123abc.com/logo.svg                                              |  ❌️   | 网站logo，有需要可自行设置               |
| BACKGROUND_URL | https://123abc.com/img.jpg                                               |  ❌️   | 背景图，有需要的可以自己设置             |

## 六、绑定自定义域名
这个网上教程太多了，油管随便搜，解析一个域名到Cloudflare，然后绑定子域名即可。
