// 域名监控系统 - Cloudflare Workers
// 简化版，支持直接部署后再配置KV

// 处理请求
async function handleRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname;
  
  // 检查是否已配置KV
  if (typeof DOMAIN_MONITOR === 'undefined') {
    return new Response(getSetupHTML(), {
      headers: { 'Content-Type': 'text/html;charset=UTF-8' },
      status: 200
    });
  }
  
  // 正常的应用逻辑将在这里
  // ...

  // 临时返回一个成功页面
  return new Response("Worker已成功部署，但需要配置KV绑定才能正常工作", {
    headers: { 'Content-Type': 'text/plain;charset=UTF-8' },
    status: 200
  });
}

// 配置引导HTML
function getSetupHTML() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>域名监控系统 - 配置向导</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body {
      font-family: 'PingFang SC', 'Microsoft YaHei', sans-serif;
      background-color: #f8f9fa;
      padding: 20px;
    }
    .setup-container {
      max-width: 800px;
      margin: 0 auto;
      background-color: white;
      border-radius: 10px;
      padding: 20px;
      box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .step {
      margin-bottom: 20px;
      padding: 15px;
      border-left: 4px solid #4e54c8;
      background-color: #f8f9fa;
    }
    .step-number {
      display: inline-block;
      width: 30px;
      height: 30px;
      background-color: #4e54c8;
      color: white;
      text-align: center;
      line-height: 30px;
      border-radius: 50%;
      margin-right: 10px;
    }
    code {
      background-color: #f1f1f1;
      padding: 2px 5px;
      border-radius: 3px;
    }
    img {
      max-width: 100%;
      border: 1px solid #ddd;
      border-radius: 4px;
      margin: 10px 0;
    }
  </style>
</head>
<body>
  <div class="setup-container">
    <h1 class="mb-4">域名监控系统 - 配置向导</h1>
    
    <div class="alert alert-info">
      <strong>提示：</strong> 您已成功部署Worker，但需要完成以下配置才能正常使用系统。
    </div>
    
    <div class="step">
      <h3><span class="step-number">1</span> 创建KV命名空间</h3>
      <p>在Cloudflare控制台中，需要创建一个KV命名空间用于存储域名数据：</p>
      <ol>
        <li>登录到您的Cloudflare控制台</li>
        <li>点击左侧菜单中的"Workers & Pages"</li>
        <li>选择"KV"选项卡</li>
        <li>点击"创建命名空间"按钮</li>
        <li>输入命名空间名称：<code>DOMAIN_MONITOR</code></li>
        <li>点击"添加"按钮创建</li>
      </ol>
    </div>
    
    <div class="step">
      <h3><span class="step-number">2</span> 绑定KV到您的Worker</h3>
      <p>创建KV命名空间后，需要将其绑定到您的Worker：</p>
      <ol>
        <li>在"Workers & Pages"中找到您部署的Worker</li>
        <li>点击Worker名称进入详情页面</li>
        <li>点击"设置"选项卡</li>
        <li>找到"变量"部分，点击"KV命名空间绑定"</li>
        <li>点击"添加绑定"按钮</li>
        <li>变量名称输入：<code>DOMAIN_MONITOR</code></li>
        <li>KV命名空间选择您刚创建的命名空间</li>
        <li>点击"保存"按钮</li>
      </ol>
    </div>
    
    <div class="step">
      <h3><span class="step-number">3</span> 配置环境变量（可选）</h3>
      <p>您可以配置以下环境变量来自定义系统：</p>
      <ul>
        <li><code>TOKEN</code> - 登录密码（默认为"domain"）</li>
        <li><code>SITE_NAME</code> - 网站标题</li>
        <li><code>TG_TOKEN</code> - Telegram机器人Token</li>
        <li><code>TG_ID</code> - Telegram聊天ID</li>
        <li><code>LOGO_URL</code> - 自定义Logo图片URL</li>
        <li><code>BACKGROUND_URL</code> - 自定义背景图片URL</li>
      </ul>
      <p>配置步骤：</p>
      <ol>
        <li>在Worker详情页面的"设置"选项卡中</li>
        <li>找到"变量"部分，点击"环境变量"</li>
        <li>点击"添加变量"按钮</li>
        <li>输入变量名和值</li>
        <li>点击"保存"按钮</li>
      </ol>
    </div>
    
    <div class="step">
      <h3><span class="step-number">4</span> 配置定时触发器（可选）</h3>
      <p>为了启用自动检查域名到期的功能，需要设置定时触发器：</p>
      <ol>
        <li>在Worker详情页面的"触发器"选项卡中</li>
        <li>找到"Cron触发器"部分</li>
        <li>点击"添加Cron触发器"</li>
        <li>输入Cron表达式：<code>0 0 * * *</code>（每天午夜运行）</li>
        <li>点击"添加"按钮</li>
      </ol>
    </div>
    
    <div class="step">
      <h3><span class="step-number">5</span> 完成配置</h3>
      <p>完成以上步骤后，刷新您的Worker页面即可开始使用域名监控系统。</p>
      <p>默认登录密码为：<code>domain</code>（除非您在环境变量中设置了TOKEN）</p>
    </div>
    
    <div class="mt-4 text-center">
      <button class="btn btn-primary" onclick="window.location.reload()">刷新页面检查配置</button>
    </div>
  </div>
</body>
</html>`;
}

// 注册Cloudflare Workers事件处理程序
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

// 注册定时任务，每天检查一次（如果已配置）
addEventListener('scheduled', event => {
  // 检查是否已配置KV
  if (typeof DOMAIN_MONITOR !== 'undefined') {
    event.waitUntil(checkExpiringDomains());
  }
});

// 占位函数，实际逻辑将在完整版本中实现
async function checkExpiringDomains() {
  console.log('检查即将到期的域名');
  // 实际检查逻辑将在这里实现
} 
