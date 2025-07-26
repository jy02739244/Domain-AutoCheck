# CF-Domain-Autocheck

## 🚨本项目主要是通过和Ai沟通创作而成，有能力者可自行进行完善或魔改🚨

* 项目是部署在Cloudflare平台的，作用只有监控域名的到期情况。
* 主要是针对那些白嫖的域名，例如`dpdns.org`之类的，可能有人注册了好几个，需要定期点击续期，或者有些白嫖的一年的域名，可以帮助进行到期监控，避免忘记到期时间。
* 主要功能：日期监控、价格记录、注册商记录、自定义标签、自定义续费链接、telegram提前通知。

## 💻界面展示
<div style="overflow: hidden; width: 300px; height: 200px;">
  <div style="display: flex; transition: transform 0.5s;">
    <img url="https://imgr2.952536.xyz/Hexo/Article/PixPin_2025-07-26_23-05-27.png" style="width: 300px; height: 200px;">
    <img url="https://imgr2.952536.xyz/Hexo/Article/PixPin_2025-07-26_23-05-13.png" style="width: 300px; height: 200px;">
    <img url="https://imgr2.952536.xyz/Hexo/Article/PixPin_2025-07-26_23-04-07.png" style="width: 300px; height: 200px;">
    <img url="https://imgr2.952536.xyz/Hexo/Article/PixPin_2025-07-26_23-05-42.png" style="width: 300px; height: 200px;">
    <img url="https://imgr2.952536.xyz/Hexo/Article/PixPin_2025-07-26_23-03-45.png" style="width: 300px; height: 200px;">
    <img url="https://imgr2.952536.xyz/Hexo/Article/20250726233245913.png" style="width: 300px; height: 200px;">
  </div>
</div>
<button onclick="prevSlide()">Previous</button>
<button onclick="nextSlide()">Next</button>

<script>
  let currentIndex = 0;
  const slides = document.querySelectorAll('div > img');
  
  function showSlide(index) {
    const slideContainer = slides[0].parentElement;
    slideContainer.style.transform = `translateX(-${index * 300}px)`;
  }

  function nextSlide() {
    currentIndex = (currentIndex + 1) % slides.length;
    showSlide(currentIndex);
  }

  function prevSlide() {
    currentIndex = (currentIndex - 1 + slides.length) % slides.length;
    showSlide(currentIndex);
  }
</script>

## 🚀简易部署流程
1. 创建workers/pages，wokers的话则粘贴代码，pages则fork仓库连接github
2. 创建一个KV，名字可以随便取
3. 绑定KV，变量名称：`DOMAIN_MONITOR`，注意大写，怕填错就复制粘贴，KV命名空间就下拉菜单选择刚才创建的KV名
4. 绑定自定义域名
5. 设定环境变量，workers可以选择在代码中改也可以在cloudflare中改，pages在cloudflare的环境变量中改，cloudflare环境变量名如下：

    > <center> 🚨 所有的变量优先级都是：Cloudflare环境变量＞代码中的变量＞默认值 🚨 </center>

    | 名称           | 示例                                                                     | 必填 | 备注                                     |
    |:---------------|:-------------------------------------------------------------------------|:----:|:-----------------------------------------|
    | TOKEN          | 默认是domain                                                             |  ✅️   | 登录密码，最好自定义，不填则默认是domain |
    | TG_TOKEN       | telegram找[@BotFather](https://t.me/BotFather)获取                       |  ❌️   | 可在界面后端配置                         |
    | TG_ID          | telegram找[@userinfobot](https://t.me/userinfobot)获取，或者群机器人也行 |  ❌️   | 可在界面后端配置                         |
    | SITE_NAME      | 默认为域名到期监控                                                       |  ❌️   | 不填，默认就是域名到期监控               |
    | LOGO_URL       | https://123abc.com/logo.svg                                              |  ❌️   | 网站logo，有需要可自行设置               |
    | BACKGROUND_URL | https://123abc.com/img.jpg                                               |  ❌️   | 背景图，有需要的可以自己设置             |

## ✍️详细部署流程，请移步👉[Faiz博客](https://blog.faiz.hidns.co/2025/07/26/Domain-AutoCheck%E5%9F%9F%E5%90%8D%E5%88%B0%E6%9C%9F%E7%9B%91%E6%8E%A7/)
