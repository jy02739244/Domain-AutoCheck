/*域名监控系统 - Cloudflare Workers*/
/*使用KV存储域名信息*/

// iconfont阿里巴巴图标库
const ICONFONT_CSS = '//at.alicdn.com/t/c/font_4973034_fdg1q0bn7c5.css';
const ICONFONT_JS = '//at.alicdn.com/t/c/font_4973034_fdg1q0bn7c5.js';

// 网站图标和背景图片，可在环境变量中设置
const DEFAULT_LOGO = 'https://imgr2.952536.xyz/Hexo/Article/domain-outline.png'; // 默认Logo图片，外置变量名为LOGO_URL
const DEFAULT_BACKGROUND = 'https://imgr2.952536.xyz/Hexo/Wallpaper/sea-station.png'; // 默认背景图片，外置变量名为BACKGROUND_URL

// 登录密码设置
const DEFAULT_TOKEN = ''; // 在此处设置默认密码，留空则使用'domain'，外置变量名为TOKEN

// Telegram通知配置
const DEFAULT_TG_TOKEN = ''; // 你的Telegram机器人Token，留空则尝试读取环境变量中TG_TOKEN的值
const DEFAULT_TG_ID = '';    // 你的Telegram聊天ID，留空则尝试读取环境变量中TG_ID的值

// 网站标题配置
const DEFAULT_TITLE = ''; // 默认网站标题，外置环境变量名为TITLE

// 登录页HTML模板
const getLoginHTML = (title) => `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${title}</title>
    <!-- 添加网站图标(favicon) -->
    <link rel="icon" href="${typeof LOGO_URL !== 'undefined' ? LOGO_URL : DEFAULT_LOGO}" type="image/png">
    <link rel="shortcut icon" href="${typeof LOGO_URL !== 'undefined' ? LOGO_URL : DEFAULT_LOGO}" type="image/png">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- 添加阿里巴巴iconfont图标库支持 -->
    <link rel="stylesheet" href="${ICONFONT_CSS}">
    <!-- 确保图标正确加载 -->
    <script src="${ICONFONT_JS}"></script>
    <style>
        body {
            margin: 0;
            padding: 0;
            height: 100vh;
            background-image: url('${typeof BACKGROUND_URL !== 'undefined' ? BACKGROUND_URL : DEFAULT_BACKGROUND}');
            background-size: cover;
            background-position: center;
            background-repeat: no-repeat;
            font-family: 'PingFang SC', 'Microsoft YaHei', sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            overflow: hidden;
        }
        
        body::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: rgba(0, 0, 0, 0.4);
            z-index: 1;
        }
        
        .github-corner {
            position: fixed;
            top: 0;
            right: 0;
            width: 0;
            height: 0;
            border-style: solid;
            border-width: 0 100px 100px 0;
            border-color: transparent rgba(53, 83, 248, 0.9) transparent transparent;
            color: white;
            text-decoration: none;
            z-index: 1000;
            transition: all 0.3s ease;
            overflow: visible; /* 确保图标不会被裁剪 */
        }
        .github-corner:hover {
            border-color: transparent rgba(99, 122, 250, 0.8) transparent transparent;
        }
        .github-corner i {
            position: absolute;
            top: 18px;
            right: -82.5px;
            font-size: 40px;
            transform: rotate(45deg); /* 顺时针旋转45度 */
            line-height: 1;
            display: inline-block; /* 确保图标有确定的尺寸 */
            width: 40px; /* 设置宽度与字体大小相同 */
            height: 40px; /* 设置高度与字体大小相同 */
            text-align: center; /* 文本居中 */
        }
        .login-container {
            background-color: rgba(255, 255, 255, 0.15);
            backdrop-filter: blur(15px);
            -webkit-backdrop-filter: blur(15px);
            border-radius: 16px;
            padding: 35px;
            width: 90%;
            max-width: 400px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
            border: 1px solid rgba(255, 255, 255, 0.18);
            position: relative;
            z-index: 10;
        }
        .login-title {
            text-align: center;
            color: #ffffff;
            margin-bottom: 25px;
            font-weight: 600;
            display: flex;
            align-items: center;
            justify-content: center;
            text-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
            margin-left: auto;
            margin-right: auto;
        }
        .login-logo {
            height: 64px;
            width: 64px;
            margin-right: 0px;
            filter: drop-shadow(0 2px 4px rgba(0, 0, 0, 0.3));
            vertical-align: middle;
        }
        .form-control {
            background-color: rgba(255, 255, 255, 0.2);
            border: 1px solid rgba(255, 255, 255, 0.3);
            padding: 14px;
            height: auto;
            color: #fff;
            font-size: 1.05rem;
            border-radius: 10px;
            backdrop-filter: blur(5px);
            -webkit-backdrop-filter: blur(5px);
            transition: all 0.3s ease;
        }
        .form-control::placeholder {
            color: rgba(255, 255, 255, 0.8);
        }
        .form-control:focus {
            background-color: rgba(255, 255, 255, 0.25);
            border-color: rgba(255, 255, 255, 0.5);
            box-shadow: 0 0 0 0.25rem rgba(255, 255, 255, 0.2);
            color: #fff;
        }
        .btn-login {
            background-color: rgba(53, 83, 248, 0.9); // 登录按钮的颜色
            border: none;
            color: white;
            padding: 12px;
            width: 100%;
            font-weight: 500;
            font-size: 1.05rem;
            border-radius: 10px;
            margin-top: 10px;
            backdrop-filter: blur(5px);
            -webkit-backdrop-filter: blur(5px);
            transition: all 0.3s ease;
            box-shadow: 0 4px 10px rgba(0, 0, 0, 0.2);
        }
        .btn-login:hover {
            background-color: rgba(99, 122, 250, 0.8);  // 登录按钮的悬停颜色
            transform: translateY(-2px);
            box-shadow: 0 6px 15px rgba(0, 0, 0, 0.3);
        }
        .error-message {
            color: #ffcccc;
            margin-top: 15px;
            text-align: center;
            display: none;
            text-shadow: 0 1px 2px rgba(0, 0, 0, 0.3);
        }
    </style>
</head>
<body>
    <a href="https://github.com/kamanfaiz" target="_blank" class="github-corner" title="GitHub Repository">
        <i class="iconfont icon-github1"></i>
    </a>
    <div class="login-container">
        <div style="display: flex; flex-direction: column; align-items: center;">
            <h2 class="login-title">
                <img src="${typeof LOGO_URL !== 'undefined' ? LOGO_URL : DEFAULT_LOGO}" alt="Logo" class="login-logo">
                ${title}
            </h2>
            <form id="loginForm" style="width: 100%;">
                <div class="mb-3">
                    <input type="password" class="form-control" id="password" placeholder="请输入访问密码" required>
                </div>
                <button type="submit" class="btn btn-login"><i class="iconfont icon-mima" style="margin-right: 5px;"></i>登录</button>
                <div id="errorMessage" class="error-message">密码错误，请重试</div>
            </form>
        </div>
    </div>
    
    <script>
        document.getElementById('loginForm').addEventListener('submit', function(e) {
            e.preventDefault();
            const password = document.getElementById('password').value;
            
            // 使用POST请求验证密码
            fetch('/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ password: password })
            })
            .then(response => {
                if (response.ok) {
                    // 密码正确，跳转到dashboard页面
                    window.location.href = '/dashboard';
                } else {
                    // 密码错误，显示错误信息
                    document.getElementById('errorMessage').style.display = 'block';
                }
            })
            .catch(error => {
                console.error('登录请求失败:', error);
                document.getElementById('errorMessage').style.display = 'block';
            });
        });
    </script>
</body>
</html>
`;

// HTML模板
const getHTMLContent = (title) => `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${title}</title>
    <!-- 添加网站图标(favicon) -->
    <link rel="icon" href="${typeof LOGO_URL !== 'undefined' ? LOGO_URL : DEFAULT_LOGO}" type="image/png">
    <link rel="shortcut icon" href="${typeof LOGO_URL !== 'undefined' ? LOGO_URL : DEFAULT_LOGO}" type="image/png">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- 添加阿里巴巴iconfont图标库支持 -->
    <link rel="stylesheet" href="${ICONFONT_CSS}">
    <!-- 确保图标正确加载 -->
    <script src="${ICONFONT_JS}"></script>
        <!-- 添加登出脚本 -->
    <script>
        // 添加登出功能
        function logout() {
            window.location.href = '/logout';
        }
    </script>
    <style>
        :root {
            --primary-color: #4e54c8;
            --secondary-color: #6c757d;
            --success-color:rgb(0, 255, 60);
            --danger-color:rgb(255, 0, 25);
            --warning-color:rgb(255, 230, 0);
            --info-color: #17a2b8;
            --light-color: #f8f9fa;
            --dark-color: #343a40;
        }
        
        body {
            font-family: 'PingFang SC', 'Microsoft YaHei', sans-serif;
            background-image: url('${typeof BACKGROUND_URL !== 'undefined' ? BACKGROUND_URL : DEFAULT_BACKGROUND}');
            background-size: cover;
            background-position: center;
            background-repeat: no-repeat;
            background-attachment: fixed;
            padding-top: 20px;
            position: relative;
            min-height: 100vh;
        }
        
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: rgba(0, 0, 0, 0.4);
            z-index: 0;
        }
        
        .navbar {
            background-color: rgba(255, 255, 255, 0.15);
            backdrop-filter: blur(15px);
            -webkit-backdrop-filter: blur(15px);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
            border: 1px solid rgba(255, 255, 255, 0.18);
            margin-bottom: 24px;
            padding: 14px 20px;
            border-radius: 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: relative;
            z-index: 2;
        }
        
        .navbar-brand {
            display: flex;
            align-items: center;
            font-weight: 600;
            color: #ffffff;
            font-size: 1.7rem;
            text-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
            gap: 2px; /* 使用gap属性统一控制子元素之间的间距 */
        }
        
        .navbar-brand i {
            font-size: 1.8rem;
            color: white;
            margin: 0; /* 移除所有margin */
        }
        
        .logo-link {
            display: flex;
            align-items: center;
            margin-right: 0px;
            text-decoration: none;
        }
        
        .logo-img {
            height: 64px;
            width: 64px;
            object-fit: contain;
            transition: transform 0.3s ease;
        }
        
        .logo-img:hover {
            transform: scale(1.1);
        }
        
        .navbar-actions {
            margin-left: auto;
            display: flex;
            align-items: center;
        }
        
        .btn-logout {
            margin-left: 10px;
            background-color: transparent;
            border: 1px solid #dc3545;
            color: #dc3545;
            padding: 5px 15px;
            border-radius: 5px;
            font-size: 0.9rem;
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .btn-logout:hover {
            background-color: #dc3545;
            color: white;
        }
        
        .container {
            max-width: 1200px;
            position: relative;
            z-index: 1;
        }
        
        .page-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
            padding: 12px 20px;
            background-color: rgba(255, 255, 255, 0.15);
            backdrop-filter: blur(15px);
            -webkit-backdrop-filter: blur(15px);
            border: 1px solid rgba(255, 255, 255, 0.18);
            border-radius: 16px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
            position: relative;
            z-index: 2;
        }
        
        .page-title {
            font-size: 1.3rem;
            font-weight: 600;
            color: #ffffff;
            margin: 0;
            display: flex;
            align-items: center;
            text-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
        }
        
        .page-title i {
            margin-right: 8px;
            font-size: 1.2rem;
        }
        
        .btn-action-group {
            display: flex;
            flex-direction: row;
            align-items: center;
            gap: 10px;
            margin-left: auto;
        }
        
        .btn-primary {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
        }
        
        .btn-primary:hover {
            background-color: #3f44ae;
            border-color: #3f44ae;
        }
        
        .card {
            border: 2px solid rgba(255, 255, 255, 0.3);
            border-radius: 16px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
            margin-bottom: 8px; /* 进一步减小卡片间的垂直间距 */
            transition: all 0.3s;
            overflow: hidden !important; /* 确保内容不会溢出 */
            position: relative;
            z-index: 1; /* 设置卡片的基础z-index */
            width: 100%;
            background-color: rgba(255, 255, 255, 0.15);
            backdrop-filter: blur(15px);
            -webkit-backdrop-filter: blur(15px);
        }
        
        .card-header {
            background-color: rgba(255, 255, 255, 0.1);
            border-bottom: 1px solid rgba(255, 255, 255, 0.18);
            padding: 15px 20px;
            position: relative;
            display: flex;
            align-items: center;
            justify-content: space-between;
            overflow: hidden; /* 防止内容溢出 */
            border-top-left-radius: 16px;
            border-top-right-radius: 16px;
            gap: 5px; /* 添加间距 */
        }
        
        .card-body .d-flex {
            margin-right: 0;
            padding-right: 0;
            overflow: visible !important;
        }
        
        /* 移除单独的百分比值样式，改为直接在SVG中使用text元素 */
        
        .card-header,
        .card-body {
            padding-left: 20px;
            padding-right: 20px;
            position: relative;
        }
        
        .card-header {
            padding-top: 12px;
            padding-bottom: 12px;
        }
        
        .domain-header {
            display: flex;
            flex-direction: column;
            justify-content: center;
            flex: 1;
            min-width: 0; /* 解决flex子项目溢出问题 */
            overflow: hidden; /* 确保内容不会溢出 */
        }
        
        .domain-header h5 {
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis; /* 添加省略号 */
            color: #ffffff;
            text-shadow: 0 1px 2px rgba(0, 0, 0, 0.3);
            font-size: 1.1rem; /* 设置域名字体大小 */
            font-weight: 600; /* 加粗字体 */
            margin-bottom: 0;
        }
        
        .domain-meta {
            font-size: 0.75rem;
            color: rgba(255, 255, 255, 0.8);
            margin-top: 3px;
        }
        
        .domain-status {
            display: flex;
            align-items: center;
            justify-content: flex-end;
            flex-shrink: 0; /* 防止被压缩 */
            min-width: 120px; /* 设置最小宽度 */
        }
        
        .domain-status .badge {
            margin-right: 10px;
            white-space: nowrap; /* 确保标签文本不换行 */
        }
        
        .progress-circle-container {
            display: flex;
            justify-content: flex-end;
            align-items: center;
            padding-right: 10px;
            box-sizing: border-box;
            overflow: visible;
            position: relative;
            z-index: 5; /* 降低z-index值 */
            min-width: 65px;
        }
        
        .progress-circle {
            position: relative;
            width: 65px;
            height: 65px;
            margin: 0;
            box-sizing: border-box;
            overflow: visible;
            z-index: 6; /* 降低z-index值 */
        }
        
        .progress-circle-bg {
            width: 100%;
            height: 100%;
            border-radius: 50%;
            border: 6px solid #f5f5f5;
            box-sizing: border-box;
            position: relative;
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 7; /* 降低z-index值 */
        }
        
        .progress-circle-value {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            display: flex;
            justify-content: center;
            align-items: center;
            font-size: 0.95rem;
            font-weight: bold;
        }
        
        .progress-ring {
            position: relative;
            transform: rotate(-90deg); /* 从12点钟方向开始 */
            z-index: 8; /* 降低z-index值 */
        }
        
        /* 添加样式使SVG中的文本不旋转 */
        .progress-ring text {
            transform: rotate(90deg); /* 抵消父元素的旋转 */
            fill: #ffffff; /* 改为白色 */
            font-size: 14px;
            font-weight: bold;
            font-family: 'PingFang SC', 'Microsoft YaHei', sans-serif;
            dominant-baseline: central;
            text-anchor: middle;
            paint-order: stroke;
            stroke: rgba(0, 0, 0, 0.3); /* 改为半透明黑色描边 */
            stroke-width: 1px;
            text-shadow: 0 1px 2px rgba(0, 0, 0, 0.3); /* 添加文字阴影 */
        }
        
        .progress-ring-circle {
            transition: stroke-dashoffset 0.35s;
            transform-origin: center;
            z-index: 9; /* 降低z-index值 */
        }
        
        /* 进度条百分比文字样式 */
        .progress-percent-text {
            font-size: 14px;
            font-weight: bold;
            color: #ffffff;
            text-shadow: 0 1px 2px rgba(0, 0, 0, 0.3);
        }
        
        .card-body {
            padding: 12px 15px;
            overflow: visible !important;
        }
        
        /* 折叠区域样式 */
        .collapse {
            margin: 0;
            padding: 0;
        }
        
        .domain-card {
            transition: all 0.3s;
        }
        
        .domain-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
        }
        
        /* 域名列样式 */
        .domain-column {
            display: flex;
            flex-direction: column;
        }
        
        /* 完全移除底部边框，仅在展开状态下显示 */
        .domain-card .card::after {
            content: none; /* 默认不显示任何内容 */
        }
        
        /* 展开状态下显示底部边框 */
        .domain-card.expanded .card {
            border-bottom: 1px solid rgba(255, 255, 255, 0.18);
            border-bottom-left-radius: 16px;
            border-bottom-right-radius: 16px;
        }
        
        /* 域名列样式 */
        .domain-column {
            display: flex;
            flex-direction: column;
        }
        
        /* 添加状态指示圆点样式 */
        .status-dot {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 10px;
            vertical-align: middle;
            flex-shrink: 0;
        }
        
        .status-dot.expired {
            background-color: var(--danger-color);
            box-shadow: 0 0 5px var(--danger-color);
        }
        
        .status-dot.warning {
            background-color: var(--warning-color);
            box-shadow: 0 0 5px var(--warning-color);
        }
        
        .status-dot.safe {
            background-color: var(--success-color);
            box-shadow: 0 0 5px var(--success-color);
        }
        
        /* 域名卡片容器样式 */
        .domain-card-container {
            margin-bottom: 12px; /* 统一设置卡片间距 */
            position: relative;
            border-radius: 16px; /* 确保容器也有圆角 */
            overflow: hidden; /* 防止内容溢出 */
        }
        
        .badge {
            padding: 5px 10px;
            border-radius: 20px;
            font-weight: 500;
            color: white;
            text-shadow: 0 1px 2px rgba(0, 0, 0, 0.3);
        }
        
        .badge .iconfont {
            margin-right: 3px;
            font-size: 0.9rem;
            vertical-align: middle;
            color: white;
        }
        
        /* 下拉按钮样式 */
        .toggle-details {
            padding: 0;
            margin-left: 5px;
            color: white;
            background: none;
            border: none;
            box-shadow: none;
            position: relative;
            width: 24px;
            height: 24px;
            display: flex;
            align-items: center;
            justify-content: center;
            line-height: 1;
            text-decoration: none !important;
            text-shadow: 0 1px 2px rgba(0, 0, 0, 0.3);
        }
        
        .toggle-details:hover {
            color: rgba(255, 255, 255, 0.8);
        }
        
        /* 图标容器样式 */
        .toggle-icon-container {
            position: relative;
            width: 16px;
            height: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: hidden; /* 防止内容溢出 */
            line-height: 1;
        }
        
        /* 箭头图标样式 */
        .toggle-icon {
            font-size: 16px;
            transition: transform 0.3s ease;
            margin-right: 0 !important; /* 覆盖默认的margin-right */
            display: block;
            line-height: 1;
        }
        
        /* 当展开时旋转箭头 */
        .toggle-details:not(.collapsed) .toggle-icon {
            transform: rotate(90deg);
        }
        
        /* 折叠内容样式 */
        .details-content {
            padding-top: 10px;
        }
        
        .domain-tag {
            display: inline-block;
            padding: 3px 8px;
            margin-left: 8px;
            border-radius: 20px;
            background-color: #f8f9fa;
            color: #666;
            font-size: 0.75rem;
            font-weight: normal;
            vertical-align: middle;
        }
        
        .domain-info {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            color: rgba(255, 255, 255, 0.8);
            font-size: 0.75rem;
        }
        
        .domain-actions {
            display: flex;
            gap: 5px;
            justify-content: flex-end;
        }
        
        .domain-actions .btn {
            padding: 5px 10px;
            font-size: 0.85rem;
        }
        
        .badge {
            padding: 5px 10px;
            border-radius: 20px;
            font-weight: 500;
        }
        
        .btn-action {
            padding: 5px 10px;
            border-radius: 6px;
            font-size: 0.8rem;
            font-weight: 500;
            transition: all 0.2s;
        }
        
        .btn-action:hover {
            /* 移除浮动效果，只保留颜色变化 */
        }
        
        .btn-outline-primary {
            color: var(--primary-color);
            border-color: var(--primary-color);
        }
        
        .btn-outline-primary:hover {
            background-color: var(--primary-color);
            color: white;
        }
        
        .btn-outline-success {
            color: var(--success-color);
            border-color: var(--success-color);
        }
        
        .btn-outline-success:hover {
            background-color: var(--success-color);
            color: white;
        }
        
        .btn-outline-danger {
            color: var(--danger-color);
            border-color: var(--danger-color);
        }
        
        .btn-outline-danger:hover {
            background-color: var(--danger-color);
            color: white;
        }
        
        .btn-outline-info {
            color: var(--info-color);
            border-color: var(--info-color);
        }
        
        .btn-outline-info:hover {
            background-color: var(--info-color);
            color: white;
        }
        
        /* 视图按钮样式 */
        .view-option {
            color: rgb(223, 223, 223) !important; /* 未选状态使用灰色文字 */
            background-color: rgba(204, 204, 204, 0.8) !important; /* 未选状态的背景色 */
            border-color:rgba(109, 109, 109, 0.3) !important; /* 修改边框颜色 */
        }
        
        .view-option.btn-info {
            background-color:rgb(255, 255, 255) !important; /* 修改选中状态背景色为蓝色 */
            color: rgb(31, 34, 39) !important; /* 选中状态使用白色文字 */
        }
        
        .view-option .view-text {
            font-weight: 500;
        }
        
        /* 添加新域名按钮自定义样式 */
        .add-domain-btn {
            background-color:rgb(42, 175, 86) !important; /* 绿色 */
            border-color:rgba(33, 148, 72, 0.8) !important;
        }
        
        .add-domain-btn:hover {
            background-color:rgb(24, 216, 120) !important; /* 深绿色 */
            border-color:rgba(38, 190, 114, 0.8) !important;
        }
        
        /* 排序按钮自定义样式 */
        .sort-btn {
            background-color: rgb(0, 123, 255) !important; /* 蓝色 */
            border-color: rgba(0, 111, 230, 0.8) !important;
        }
        
        .sort-btn:hover {
            background-color: rgb(0, 162, 255) !important; /* 蓝色 */
            border-color: rgba(23, 137, 202, 0.8) !important;
            
        }
        
        /* 排序选项的勾选图标样式 */
        .sort-check {
            visibility: hidden;
            margin-right: 5px;
            /* 使用与文字相同的颜色 */
            color: inherit;
        }
        
        .sort-option.active .sort-check {
            visibility: visible;
        }
        
        /* 排序选项选中状态样式 - 只显示勾符号，不使用背景色 */
        .sort-option.active {
            background-color: transparent !important;
            color: white !important;
        }
        
        /* 确保所有排序选项文字左对齐 */
        .dropdown-item {
            display: flex;
            align-items: center;
        }
        
        /* 添加iconfont图标的通用样式 */
        .iconfont {
            font-size: 1rem;
            vertical-align: middle;
            margin-right: 4px;
        }
        
        /* 按钮中的图标特殊样式 */
        .btn-action .iconfont {
            font-size: 0.9rem;
        }
        
        /* 表单和模态框中的图标统一样式 */
        .modal-body .iconfont {
            color: #555;
        }
        
        /* 大号图标样式 */
        .iconfont-lg {
            font-size: 1.5rem;
        }
        
        /* 不同颜色的图标 */
        .icon-primary { color: var(--primary-color); }
        .icon-success { color: var(--success-color); }
        .icon-danger { color: var(--danger-color); }
        .icon-warning { color: var(--warning-color); }
        .icon-info { color: var(--info-color); }
        
        .domain-actions {
            display: flex;
            justify-content: space-between;
            margin-top: 10px;
            gap: 5px;
            margin-bottom: 8px;
        }
        
        .domain-actions .btn {
            flex-grow: 1;
            text-align: center;
            padding: 8px 0;
            border-radius: 6px;
            font-weight: 500;
            font-size: 0.85rem;
        }
        
        /* 纯图标按钮样式 - 用于替换文字按钮 */
        .btn-icon-only {
            width: 40px;
            height: 40px;
            padding: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 50%;
            flex-grow: 1;
            max-width: 40px;
        }
        
        .btn-icon-only .iconfont {
            margin: 0;
            font-size: 1.2rem;
        }
        
        /* 纯图标链接样式 */
        .link-icon-only {
            width: 40px;
            height: 40px;
            padding: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 50%;
            flex-grow: 1;
            max-width: 40px;
        }
        
        .link-icon-only .iconfont {
            margin: 0;
            font-size: 1.2rem;
        }
        
        /* 域名操作按钮行样式 */
        .domain-actions {
            display: flex;
            justify-content: space-between;
            gap: 3px;
            margin-top: 12px;
            margin-bottom: 8px;
            flex-wrap: nowrap;
            width: 100%;
        }
        
        .domain-actions .btn,
        .domain-actions a.btn {
            flex: 1;
            padding: 6px 2px;
            font-size: 0.7rem;
            white-space: nowrap;
            text-align: center;
            overflow: hidden;
            text-overflow: ellipsis;
            color: white;
            border: none;
            backdrop-filter: blur(5px);
            -webkit-backdrop-filter: blur(5px);
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
            transition: all 0.3s ease;
        }
        
        .domain-actions .btn:hover,
        .domain-actions a.btn:hover {
            /* 移除浮动效果，只保留颜色变化 */
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
            color: white;
        }
        
        .domain-actions .iconfont {
            margin-right: 2px;
            font-size: 0.85rem;
            display: inline-block !important;
            vertical-align: middle;
            color: white;
        }
        
        /* 按钮颜色 */
        .btn-primary, .btn-outline-primary {
            background-color: rgba(47, 103, 167, 0.9);
            border-color: rgba(37, 86, 141, 0.3);
        }
        
        /* 在这里添加悬停样式 */
        .btn-primary:hover {
            background-color: rgba(0, 119, 255, 0.7);
            border-color: rgba(0, 119, 255, 0.3);
        }
        
        .btn-success, .btn-outline-success {
            background-color: rgba(40, 167, 69, 0.7);
            border-color: rgba(40, 167, 69, 0.3);
        }

        .btn-success:hover {
            background-color: rgba(69, 211, 102, 0.8);
            border-color: rgba(47, 196, 81, 0.3);
        }
        
        .btn-info, .btn-outline-info {
            background-color: rgba(23, 162, 184, 0.7);
            border-color: rgba(23, 162, 184, 0.3);
        }
        
        .btn-warning, .btn-outline-warning {
            background-color: rgba(255, 193, 7, 0.7);
            border-color: rgba(255, 193, 7, 0.3);
        }
        
        .btn-danger, .btn-outline-danger {
            background-color: rgba(220, 53, 69, 0.7);
            border-color: rgba(220, 53, 69, 0.3);
        }
        
        .btn-secondary, .btn-outline-secondary {
            background-color: rgba(108, 117, 125, 0.7);
            border-color: rgba(108, 117, 125, 0.3);
        }
        
        /* 续期链接样式已整合到按钮行中 */
        
        .test-notify-btn {
            width: 100%;
            border-radius: 6px;
            padding: 8px 0;
            font-weight: 500;
            font-size: 0.85rem;
            background-color: white;
            border: 1px solid #17a2b8;
            color: #17a2b8;
        }
        
        .test-notify-btn:hover {
            background-color: #17a2b8;
            color: white;
        }
        
        .card-text {
            margin-bottom: 6px;
            color: rgba(255, 255, 255, 0.9);
            font-size: 0.85rem;
            display: flex;
            align-items: center;
            padding-left: 2px;
        }
        
        .card-text strong {
            color: #ffffff;
            font-weight: 600;
            font-size: 0.85rem;
            margin-right: 4px;
            text-shadow: 0 1px 2px rgba(0, 0, 0, 0.3);
        }
        
        .card-text .iconfont {
            margin-right: 6px;
            color: rgba(255, 255, 255, 0.9);
            font-size: 0.85rem;
            width: 16px;
            text-align: center;
            display: inline-flex;
            justify-content: center;
        }
        
        .modal-content {
            border-radius: 16px;
            border: 1px solid rgba(255, 255, 255, 0.18);
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            background-color: rgba(255, 255, 255, 0.15);
            backdrop-filter: blur(15px);
            -webkit-backdrop-filter: blur(15px);
        }
        
        .modal-header {
            border-bottom: 1px solid rgba(255, 255, 255, 0.18);
            background-color: rgba(255, 255, 255, 0.1);
            padding: 15px 20px;
            color: white;
            text-shadow: 0 1px 2px rgba(0, 0, 0, 0.3);
        }
        
        .modal-footer {
            border-top: 1px solid rgba(255, 255, 255, 0.18);
            padding: 15px 20px;
            background-color: rgba(255, 255, 255, 0.05);
        }
        
        /* 确保下拉菜单显示在最上层 */
        .dropdown-menu {
            z-index: 1050 !important;
            background-color: rgba(60, 65, 70, 0.75) !important; /* 更浅的背景色 */
            backdrop-filter: blur(15px) !important;
            -webkit-backdrop-filter: blur(15px) !important;
            border: 1px solid rgba(255, 255, 255, 0.25) !important;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.35) !important;
            padding: 8px !important;
            border-radius: 10px !important;
        }
        
        .dropdown-item {
            font-size: 0.85rem;
            padding: 0.5rem 1rem;
            color: white !important;
            border-radius: 6px;
            margin-bottom: 2px;
            font-weight: 500;
            text-shadow: 0 1px 2px rgba(0, 0, 0, 0.3);
        }
        
        .dropdown-item:hover {
            background-color: rgba(255, 255, 255, 0.25) !important;
            color: white !important;
        }
        
        .dropdown-divider {
            border-top: 1px solid rgba(255, 255, 255, 0.25) !important;
            margin: 6px 0;
        }
        
        /* 自定义间距类 */
        .px-1-5 {
            padding-left: 0.375rem !important;
            padding-right: 0.375rem !important;
        }
        
        .form-label {
            font-weight: 500;
            color: white;
            display: flex;
            align-items: center;
            gap: 5px;
            text-shadow: 0 1px 2px rgba(0, 0, 0, 0.3);
        }
        
        .form-label .iconfont,
        .modal-body h6 .iconfont,
        .modal-body .form-text .iconfont {
            color: rgba(255, 255, 255, 0.9);
            margin-right: 0;
            font-size: 0.95rem;
        }
        
        .modal-body {
            color: white;
        }
        
        .modal-body .form-text {
            color: rgba(255, 255, 255, 0.8);
        }
        
        .form-control {
            border-radius: 10px;
            border: 1px solid rgba(255, 255, 255, 0.3);
            padding: 10px 15px;
            background-color: rgba(255, 255, 255, 0.2);
            color: white;
            backdrop-filter: blur(5px);
            -webkit-backdrop-filter: blur(5px);
        }
        
        .form-control:focus {
            border-color: rgba(255, 255, 255, 0.5);
            box-shadow: 0 0 0 0.2rem rgba(255, 255, 255, 0.25);
            background-color: rgba(255, 255, 255, 0.25);
            color: white;
        }
        
        .form-control::placeholder {
            color: rgba(255, 255, 255, 0.7);
        }
        
        .form-select {
            background-color: rgba(255, 255, 255, 0.2);
            border: 1px solid rgba(255, 255, 255, 0.3);
            color: white;
            border-radius: 10px;
            backdrop-filter: blur(5px);
            -webkit-backdrop-filter: blur(5px);
        }
        
        .form-select:focus {
            border-color: rgba(255, 255, 255, 0.5);
            box-shadow: 0 0 0 0.2rem rgba(255, 255, 255, 0.25);
            background-color: rgba(255, 255, 255, 0.25);
        }
        
        /* 添加select下拉选项的样式 */
        .form-select option {
            background-color: #333;
            color: white;
            padding: 8px;
        }
        
        .alert {
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.05);
        }
        
        @media (max-width: 768px) {
            .domain-card {
                flex-direction: column;
            }
            
            .domain-card .card-header {
                width: 100%;
                border-right: none;
                border-bottom: 1px solid rgba(255, 255, 255, 0.18);
            }
            
            .domain-card .btn {
                padding: 0.2rem 0.3rem;
                font-size: 0.65rem;
            }
            
            .domain-actions {
                flex-wrap: nowrap;
                gap: 2px;
                margin-top: 8px;
                margin-bottom: 5px;
            }
            
            .domain-actions .btn,
            .domain-actions a.btn {
                padding: 3px 1px;
                font-size: 0.65rem;
            }
            
            .domain-actions .iconfont {
                margin-right: 1px;
                font-size: 0.75rem;
            }
            
            .page-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }
            
            .btn-action-group {
                width: 100%;
                display: flex;
                justify-content: flex-end;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- 导航栏 -->
        <nav class="navbar">
            <span class="navbar-brand">
                <span class="logo-link">
                    <img src="${typeof LOGO_URL !== 'undefined' ? LOGO_URL : DEFAULT_LOGO}" alt="Logo" class="logo-img">
                </span>
                <i class="iconfont icon-domain iconfont-lg"></i>
                <span style="color: white; text-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);">${title}</span>
            </span>
            <div class="navbar-actions">
                <button class="btn btn-secondary me-3" data-bs-toggle="modal" data-bs-target="#settingsModal">
                    <i class="iconfont icon-gear" style="color: white;"></i> <span style="color: white;">系统设置</span>
                </button>
                <button class="btn btn-danger" onclick="logout()">
                    <i class="iconfont icon-sign-out-alt" style="color: white;"></i> <span style="color: white;">退出</span>
                </button>
            </div>
        </nav>
        
        <!-- 页面标题和操作按钮 -->
        <div class="page-header">
            <h1 class="page-title"><i class="iconfont icon-list-ul"></i> 域名列表</h1>
            <div class="btn-action-group">
                                  <div class="btn-group me-2">
                      <button class="btn btn-outline-info btn-action view-option" data-view="collapse-all" type="button" style="transition: background-color 0.2s, color 0.2s;">
                         <i class="iconfont icon-quanjusuoxiao"></i> <span class="view-text">全局折叠</span>
                      </button>
                      <button class="btn btn-outline-info btn-action view-option" data-view="expand-all" type="button" style="transition: background-color 0.2s, color 0.2s;">
                         <i class="iconfont icon-quanjufangda"></i> <span class="view-text">全局展开</span>
                      </button>
                  </div>
                <button class="btn btn-primary btn-action add-domain-btn" data-bs-toggle="modal" data-bs-target="#addDomainModal">
                    <i class="iconfont icon-jia" style="color: white;"></i> <span style="color: white;">添加新域名</span>
                </button>
                <div class="dropdown">
                    <button class="btn btn-danger dropdown-toggle btn-action sort-btn" type="button" id="sortDropdown" data-bs-toggle="dropdown" aria-expanded="false">
                        <i class="iconfont icon-paixu" style="color: white;"></i> <span style="color: white;">按域名升序</span>
                    </button>
                    <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="sortDropdown">
                        <li><a class="dropdown-item sort-option" data-sort="name" data-order="asc" href="#"><i class="iconfont icon-gou1 sort-check"></i> 按域名升序</a></li>
                        <li><a class="dropdown-item sort-option" data-sort="name" data-order="desc" href="#"><i class="iconfont icon-gou1 sort-check"></i> 按域名降序</a></li>
                        <li><hr class="dropdown-divider"></li>
                        <li><a class="dropdown-item sort-option" data-sort="daysLeft" data-order="asc" href="#"><i class="iconfont icon-gou1 sort-check"></i> 按剩余天数升序</a></li>
                        <li><a class="dropdown-item sort-option" data-sort="daysLeft" data-order="desc" href="#"><i class="iconfont icon-gou1 sort-check"></i> 按剩余天数降序</a></li>
                        <li><hr class="dropdown-divider"></li>
                        <li><a class="dropdown-item sort-option" data-sort="registrar" data-order="asc" href="#"><i class="iconfont icon-gou1 sort-check"></i> 按注册商升序</a></li>
                        <li><a class="dropdown-item sort-option" data-sort="registrar" data-order="desc" href="#"><i class="iconfont icon-gou1 sort-check"></i> 按注册商降序</a></li>
                    </ul>
                </div>
            </div>
        </div>
        
        <div class="row g-1" id="domainListContainer">
            <!-- 域名卡片将通过JavaScript动态生成 -->
            <div class="col-md-6 col-lg-4 domain-column px-1-5" id="column-1"></div>
            <div class="col-md-6 col-lg-4 domain-column px-1-5" id="column-2"></div>
            <div class="col-md-6 col-lg-4 domain-column px-1-5" id="column-3"></div>
        </div>
    </div>
    
    <!-- 添加域名模态框 -->
    <div class="modal fade" id="addDomainModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">添加新域名</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <form id="addDomainForm">
                        <input type="hidden" id="domainId" value="">
                        <div class="mb-3">
                            <label for="domainName" class="form-label"><i class="iconfont icon-earth-full"></i> 域名</label>
                            <input type="text" class="form-control" id="domainName" required>
                        </div>
                        <div class="mb-3">
                            <label for="registrar" class="form-label"><i class="iconfont icon-house-chimney"></i> 注册商</label>
                            <input type="text" class="form-control" id="registrar">
                        </div>
                        <div class="mb-3">
                            <label for="registrationDate" class="form-label"><i class="iconfont icon-calendar-days"></i> 注册时间</label>
                            <input type="date" class="form-control" id="registrationDate">
                            <div class="form-text">域名首次注册的时间（可选）</div>
                        </div>
                        <div class="mb-3">
                            <label for="expiryDate" class="form-label"><i class="iconfont icon-calendar-days"></i> 到期日期</label>
                            <input type="date" class="form-control" id="expiryDate" required>
                        </div>
                        
                        <!-- 价格设置 -->
                        <div class="mb-3">
                            <label for="price" class="form-label"><i class="iconfont icon-licai"></i> 价格</label>
                            <div class="input-group">
                                <select class="form-select" id="priceCurrency" style="max-width: 80px;">
                                    <option value="¥" selected>¥</option>
                                    <option value="$">$</option>
                                    <option value="€">€</option>
                                    <option value="£">£</option>
                                    <option value="₽">₽</option>
                                </select>
                                <input type="number" class="form-control" id="priceValue" value="" min="0" step="0.01" placeholder="输入价格">
                                <select class="form-select" id="priceUnit" style="max-width: 110px;">
                                    <option value="year" selected>年</option>
                                    <option value="month">月</option>
                                    <option value="day">日</option>
                                </select>
                            </div>
                            <div class="form-text">域名的价格（可选）</div>
                        </div>
                        
                        <!-- 续期周期设置 -->
                        <div class="mb-3">
                            <label for="renewCycle" class="form-label"><i class="iconfont icon-repeat"></i> 续期周期</label>
                            <div class="input-group">
                                <input type="number" class="form-control" id="renewCycleValue" value="1" min="1" max="100">
                                <select class="form-select" id="renewCycleUnit">
                                    <option value="year" selected>年</option>
                                    <option value="month">月</option>
                                    <option value="day">日</option>
                                </select>
                            </div>
                            <div class="form-text">域名的常规续期周期，用于计算进度条</div>
                        </div>
                        
                        <!-- 添加续费链接字段 -->
                        <div class="mb-3">
                            <label for="renewLink" class="form-label"><i class="iconfont icon-link"></i> 续费链接</label>
                            <input type="url" class="form-control" id="renewLink" placeholder="https://example.com/renew">
                            <div class="form-text">域名续费的直达链接（可选）</div>
                        </div>
                        
                        <!-- 上次续期时间设置 -->
                        <div class="mb-3" id="lastRenewedContainer" style="display: none;">
                            <div class="d-flex align-items-center">
                                <label class="form-label mb-0 me-3">上次续期时间:</label>
                                <span id="lastRenewedDisplay" class="text-white me-2"></span>
                                <button type="button" class="btn btn-sm btn-danger" id="clearLastRenewed"><span style="color: white;">清除</span></button>
                            </div>
                            <input type="hidden" id="lastRenewed" value="">
                            <div class="form-text">清除后将不再显示上次续期信息，请慎重操作！！</div>
                        </div>
                        
                        <!-- 通知设置 -->
                        <hr>
                        <h6 class="mb-3" style="display: flex; align-items: center; gap: 5px;"><i class="iconfont icon-paper-plane" style="color: white;"></i> 通知设置</h6>
                        <div class="mb-3 form-check">
                            <input type="checkbox" class="form-check-input" id="useGlobalSettings" checked>
                            <label class="form-check-label" for="useGlobalSettings">使用全局通知设置</label>
                        </div>
                        <div id="domainNotifySettings" style="display: none;">
                            <div class="mb-3 form-check">
                                <input type="checkbox" class="form-check-input" id="notifyEnabled" checked>
                                <label class="form-check-label" for="notifyEnabled">启用到期通知</label>
                            </div>
                            <div class="mb-3">
                                <label for="domainNotifyDays" class="form-label"><i class="iconfont icon-lingdang"></i> 提前通知天数</label>
                                <input type="number" class="form-control" id="domainNotifyDays" min="1" max="90" value="30">
                            </div>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal"><span style="color: white;">取消</span></button>
                    <button type="button" class="btn btn-primary" id="saveDomainBtn"><span style="color: white;">保存</span></button>
                </div>
            </div>
        </div>
    </div>
    
    <!-- 设置模态框 -->
    <div class="modal fade" id="settingsModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">系统设置</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <form id="settingsForm">
                        <h6 class="mb-3" style="display: flex; align-items: center; gap: 5px;"><i class="iconfont icon-telegram" style="color: white;"></i> Telegram通知设置</h6>
                        <div class="mb-3 form-check">
                            <input type="checkbox" class="form-check-input" id="telegramEnabled">
                            <label class="form-check-label" for="telegramEnabled">启用Telegram通知</label>
                        </div>
                        <div id="telegramSettings" style="display: none;">
                            <div class="mb-3">
                                <label for="telegramToken" class="form-label"><i class="iconfont icon-key"></i> 机器人Token</label>
                                <input type="text" class="form-control" id="telegramToken" placeholder="如已在环境变量中配置则可留空">
                                <div class="form-text">在Telegram中找到@BotFather创建机器人并获取Token</div>
                            </div>
                            <div class="mb-3">
                                <label for="telegramChatId" class="form-label"><i class="iconfont icon-robot-2-fill"></i> 聊天ID</label>
                                <input type="text" class="form-control" id="telegramChatId" placeholder="如已在环境变量中配置则可留空">
                                <div class="form-text">可以使用@userinfobot获取个人ID，或将机器人添加到群组后获取群组ID</div>
                            </div>
                            <div class="mb-3">
                                <label for="notifyDays" class="form-label"><i class="iconfont icon-lingdang"></i> 提前通知天数</label>
                                <input type="number" class="form-control" id="notifyDays" min="1" max="90" value="30">
                                <div class="form-text">域名到期前多少天开始发送通知</div>
                            </div>
                            <div class="mb-3">
                                <button type="button" class="btn btn-info" id="testTelegramBtn"><i class="iconfont icon-paper-plane" style="color: white;"></i> <span style="color: white;">测试Telegram通知</span></button>
                                <span id="testResult" class="ms-2"></span>
                            </div>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal"><span style="color: white;">取消</span></button>
                    <button type="button" class="btn btn-primary" id="saveSettingsBtn"><span style="color: white;">保存设置</span></button>
                </div>
            </div>
        </div>
    </div>
    
    <!-- 确认删除模态框 -->
    <div class="modal fade" id="deleteDomainModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">确认删除</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <p>确定要删除域名 <span id="deleteModalDomainName"></span> 吗？此操作不可撤销。</p>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal"><span style="color: white;">取消</span></button>
                    <button type="button" class="btn btn-danger" id="confirmDeleteBtn"><span style="color: white;">删除</span></button>
                </div>
            </div>
        </div>
    </div>
    
    <!-- 续期模态框 -->
    <div class="modal fade" id="renewDomainModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">域名续期</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <p>为域名 <span id="renewModalDomainName"></span> 续期</p>
                    <div class="mb-3">
                        <label for="renewPeriod" class="form-label"><i class="iconfont icon-repeat"></i> 续期周期</label>
                        <div class="input-group">
                            <input type="number" class="form-control" id="renewPeriodValue" min="1" max="100" value="1">
                            <select class="form-select" id="renewPeriodUnit">
                                <option value="year" selected>年</option>
                                <option value="month">月</option>
                                <option value="day">日</option>
                            </select>
                        </div>
                    </div>
                    <div class="mb-3">
                        <label for="newExpiryDate" class="form-label"><i class="iconfont icon-calendar-days"></i> 新到期日期</label>
                        <input type="date" class="form-control" id="newExpiryDate" readonly>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                    <button type="button" class="btn btn-success" id="confirmRenewBtn">确认续期</button>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <!-- 已在头部引入iconfont图标库，此处无需重复引入 -->
    <script>
        // 全局变量
        let domains = [];
        let currentDomainId = null;
        let telegramConfig = {};
        let currentSortField = 'name'; // 默认排序字段改为域名
        let currentSortOrder = 'asc'; // 默认排序顺序
        let viewMode = 'auto-collapse'; // 默认查看模式：auto-collapse (自动折叠), expand-all (全部展开), collapse-all (全部折叠)
        
        // 将天数转换为年月日格式
        function formatDaysToYMD(days) {
          if (days <= 0) return '';
          
          const years = Math.floor(days / 365);
          const remainingDaysAfterYears = days % 365;
          const months = Math.floor(remainingDaysAfterYears / 30);
          const remainingDays = remainingDaysAfterYears % 30;
          
          let result = '';
          
          if (years > 0) {
            result += years + '年';
          }
          
          if (months > 0) {
            result += months + '个月';
          }
          
          if (remainingDays > 0) {
            result += remainingDays + '天';
          }
          
          return result;
        }
        
        // 页面加载完成后执行
        document.addEventListener('DOMContentLoaded', () => {
            loadDomains();
            loadTelegramConfig();
            setupEventListeners();
            
            // 设置初始视图模式为全部折叠
            setTimeout(() => {
                const collapseAllButton = document.querySelector('.view-option[data-view="collapse-all"]');
                if (collapseAllButton) {
                    collapseAllButton.classList.remove('btn-outline-info');
                    collapseAllButton.classList.add('btn-info');
                }
            }, 500); // 延迟执行确保DOM已经加载完成
        });
        
        // 设置事件监听器
        function setupEventListeners() {
            // 保存域名按钮
            document.getElementById('saveDomainBtn').addEventListener('click', saveDomain);
            
            // 确认删除按钮
            document.getElementById('confirmDeleteBtn').addEventListener('click', deleteDomain);
            
            // 确认续期按钮
            document.getElementById('confirmRenewBtn').addEventListener('click', renewDomain);
            
            // 清除上次续期时间按钮
            document.getElementById('clearLastRenewed').addEventListener('click', function() {
                document.getElementById('lastRenewed').value = '';
                document.getElementById('lastRenewedDisplay').textContent = '已清除';
                document.getElementById('lastRenewedDisplay').classList.add('text-danger');
            });
            
            // 续期值或单位变化时更新新到期日期
            document.getElementById('renewPeriodValue').addEventListener('input', updateNewExpiryDate);
            document.getElementById('renewPeriodUnit').addEventListener('change', updateNewExpiryDate);
            
            // Telegram启用状态变化
            document.getElementById('telegramEnabled').addEventListener('change', function() {
                document.getElementById('telegramSettings').style.display = this.checked ? 'block' : 'none';
            });
            
            // 保存设置按钮
            document.getElementById('saveSettingsBtn').addEventListener('click', saveSettings);
            
            // 测试Telegram按钮
            document.getElementById('testTelegramBtn').addEventListener('click', testTelegram);
            
            // 域名通知设置 - 全局/自定义切换
            document.getElementById('useGlobalSettings').addEventListener('change', function() {
                document.getElementById('domainNotifySettings').style.display = this.checked ? 'none' : 'block';
            });
            
            // 排序选项点击事件
            document.querySelectorAll('.sort-option').forEach(option => {
                option.addEventListener('click', function(e) {
                    e.preventDefault();
                    currentSortField = this.dataset.sort;
                    currentSortOrder = this.dataset.order;
                    renderDomainList();
                    
                    // 更新排序按钮文本
                    const sortText = this.textContent.trim();
                    document.getElementById('sortDropdown').innerHTML = '<i class="iconfont icon-paixu"></i> ' + sortText;
                    
                    // 更新勾选状态
                    document.querySelectorAll('.sort-option').forEach(opt => {
                        opt.classList.remove('active');
                    });
                    this.classList.add('active');
                });
            });
            
            // 视图模式选项点击事件
            document.querySelectorAll('.view-option').forEach(option => {
                option.addEventListener('click', function(e) {
                    const newViewMode = this.dataset.view;
                    
                    // 设置视图模式
                    viewMode = newViewMode;
                    
                    // 直接获取所有卡片详情元素
                    const allDetails = document.querySelectorAll('.domain-card .collapse');
                    
                    // 根据模式直接进行操作
                    if (newViewMode === 'expand-all') {
                        console.log('展开所有卡片，共 ' + allDetails.length + ' 个');
                        
                        // 直接展开所有卡片
                        allDetails.forEach(detail => {
                            // 手动添加show类，强制显示
                            detail.classList.add('show');
                            detail.style.height = 'auto'; // 确保内容显示
                            detail.style.overflow = 'visible';
                            
                            // 获取父级卡片
                            const domainCard = detail.closest('.domain-card');
                            if (domainCard) {
                                // 在父级卡片中寻找toggle按钮
                                const btn = domainCard.querySelector('.toggle-details');
                                if (btn) {
                                    btn.classList.remove('collapsed');
                                    btn.setAttribute('aria-expanded', 'true');
                                }
                            }
                        });
                        
                        // 高亮"全部展开"按钮
                        document.querySelectorAll('.view-option').forEach(btn => {
                            if (btn.dataset.view === 'expand-all') {
                                btn.classList.remove('btn-outline-info');
                                btn.classList.add('btn-info');
                            } else {
                                btn.classList.add('btn-outline-info');
                                btn.classList.remove('btn-info');
                            }
                        });
                    } else if (newViewMode === 'collapse-all' || newViewMode === 'auto-collapse') {
                        console.log('折叠所有卡片，共 ' + allDetails.length + ' 个');
                        
                        // 直接折叠所有卡片
                        allDetails.forEach(detail => {
                            // 手动移除show类，强制隐藏
                            detail.classList.remove('show');
                            detail.style.height = '0px'; // 强制隐藏高度
                            detail.style.overflow = 'hidden';
                            
                            // 获取父级卡片
                            const domainCard = detail.closest('.domain-card');
                            if (domainCard) {
                                // 在父级卡片中寻找toggle按钮
                                const btn = domainCard.querySelector('.toggle-details');
                                if (btn) {
                                    btn.classList.add('collapsed');
                                    btn.setAttribute('aria-expanded', 'false');
                                }
                            }
                        });
                        
                        // 高亮"全部折叠"按钮
                        document.querySelectorAll('.view-option').forEach(btn => {
                            if (btn.dataset.view === 'collapse-all') {
                                btn.classList.remove('btn-outline-info');
                                btn.classList.add('btn-info');
                            } else {
                                btn.classList.add('btn-outline-info');
                                btn.classList.remove('btn-info');
                            }
                        });
                    }
                });
            });
            
            // 初始加载时设置默认排序选项
            const defaultSortOption = document.querySelector('.sort-option[data-sort="' + currentSortField + '"][data-order="' + currentSortOrder + '"]');
            if (defaultSortOption) {
                // 设置排序按钮文本
                document.getElementById('sortDropdown').innerHTML = '<i class="iconfont icon-paixu"></i> ' + defaultSortOption.textContent.trim();
                
                // 设置默认选项为激活状态
                defaultSortOption.classList.add('active');
            }
            
            // 表头排序点击事件
            document.addEventListener('click', function(e) {
                if (e.target.tagName === 'TH') {
                    const field = e.target.dataset.sort;
                    if (field) {
                        if (currentSortField === field) {
                            // 切换排序顺序
                            currentSortOrder = currentSortOrder === 'asc' ? 'desc' : 'asc';
                        } else {
                            currentSortField = field;
                            currentSortOrder = 'asc';
                        }
                        renderDomainList();
                    }
                }
            });
        }
        
        // 加载所有域名
        async function loadDomains() {
            try {
                const response = await fetch('/api/domains');
                if (!response.ok) throw new Error('获取域名列表失败');
                
                domains = await response.json();
                renderDomainList();
            } catch (error) {
                showAlert('danger', '加载域名列表失败: ' + error.message);
            }
        }
        
        // 加载Telegram配置
        async function loadTelegramConfig() {
            try {
                const response = await fetch('/api/telegram/config');
                if (!response.ok) throw new Error('获取Telegram配置失败');
                
                telegramConfig = await response.json();
                
                // 更新表单
                document.getElementById('telegramEnabled').checked = telegramConfig.enabled;
                document.getElementById('telegramSettings').style.display = telegramConfig.enabled ? 'block' : 'none';
                document.getElementById('notifyDays').value = telegramConfig.notifyDays || 30;
                
                // 处理聊天ID的显示
                if (telegramConfig.chatIdFromEnv) {
                    // 如果聊天ID来自环境变量，显示固定文本
                    document.getElementById('telegramChatId').value = '';
                    document.getElementById('telegramChatId').placeholder = '已通过环境变量配置';
                    document.getElementById('telegramChatId').disabled = false; // 允许用户编辑
                } else {
                    // 显示用户设置的聊天ID
                    document.getElementById('telegramChatId').value = telegramConfig.chatId || '';
                    document.getElementById('telegramChatId').placeholder = '如已在环境变量中配置则可留空';
                    document.getElementById('telegramChatId').disabled = false;
                }
                
                // 处理Token的显示
                if (telegramConfig.tokenFromEnv) {
                    // 如果Token来自环境变量，显示固定文本
                    document.getElementById('telegramToken').value = '';
                    document.getElementById('telegramToken').placeholder = '已通过环境变量配置';
                    document.getElementById('telegramToken').disabled = false; // 允许用户编辑
                } else {
                    // 显示用户设置的Token
                    document.getElementById('telegramToken').value = telegramConfig.botToken || '';
                    document.getElementById('telegramToken').placeholder = '如已在环境变量中配置则可留空';
                    document.getElementById('telegramToken').disabled = false;
                }
            } catch (error) {
                console.error('加载Telegram配置失败:', error);
            }
        }
        
        // 保存设置
        async function saveSettings() {
            const enabled = document.getElementById('telegramEnabled').checked;
            // 获取表单值，即使是空字符串也保留
            const botToken = document.getElementById('telegramToken').value;
            const chatId = document.getElementById('telegramChatId').value;
            const notifyDays = parseInt(document.getElementById('notifyDays').value) || 30;
            
            try {
                const response = await fetch('/api/telegram/config', {
                    headers: { 'Content-Type': 'application/json' },
                    method: 'POST',
                    body: JSON.stringify({
                        enabled,
                        botToken,
                        chatId,
                        notifyDays
                    })
                });
                
                if (!response.ok) {
                    try {
                        const error = await response.json();
                        throw new Error(error.error || '保存设置失败');
                    } catch (jsonError) {
                        // 如果响应不是JSON格式，直接使用状态文本
                        throw new Error('保存设置失败: ' + response.statusText);
                    }
                }
                
                telegramConfig = await response.json();
                showAlert('success', '设置保存成功');
                
                // 关闭模态框
                bootstrap.Modal.getInstance(document.getElementById('settingsModal')).hide();
            } catch (error) {
                showAlert('danger', error.message);
            }
        }
        
        // 测试Telegram通知
        async function testTelegram() {
            const testResult = document.getElementById('testResult');
            testResult.textContent = '发送中...';
            testResult.className = 'ms-2 text-info';
            
            try {
                const response = await fetch('/api/telegram/test', {
                    method: 'POST'
                });
                
                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.error || '测试失败');
                }
                
                const result = await response.json();
                testResult.textContent = '测试成功！请检查Telegram是否收到消息';
                testResult.className = 'ms-2 text-success';
            } catch (error) {
                testResult.textContent = '测试失败: ' + error.message;
                testResult.className = 'ms-2 text-danger';
            }
        }
        
        // 渲染域名列表
function renderDomainList() {
    // 获取三个列容器
    const column1 = document.getElementById('column-1');
    const column2 = document.getElementById('column-2');
    const column3 = document.getElementById('column-3');
    
    // 清空所有列
    column1.innerHTML = '';
    column2.innerHTML = '';
    column3.innerHTML = '';
    
    if (domains.length === 0) {
        // 清除列结构
        document.getElementById('domainListContainer').innerHTML = '<div class="col-12"><div class="alert alert-info">暂无域名记录，请点击右上角按钮添加域名。</div></div>';
        return;
    } else {
                    // 确保列结构存在
            if (column1 === null || column2 === null || column3 === null) {
                const domainListContainer = document.getElementById('domainListContainer');
                domainListContainer.innerHTML = 
                    '<div class="col-md-6 col-lg-4 domain-column px-1-5" id="column-1"></div>' +
                    '<div class="col-md-6 col-lg-4 domain-column px-1-5" id="column-2"></div>' +
                    '<div class="col-md-6 col-lg-4 domain-column px-1-5" id="column-3"></div>';
            
            // 重新获取列容器
            const newColumn1 = document.getElementById('column-1');
            const newColumn2 = document.getElementById('column-2');
            const newColumn3 = document.getElementById('column-3');
            columns = [newColumn1, newColumn2, newColumn3];
        }
    }
    
    // 获取列容器数组，用于循环分配卡片
    const columns = [column1, column2, column3];
    
    // 获取全局通知设置
    const globalNotifyDays = telegramConfig.notifyDays || 30;
    
    // 计算每个域名的剩余天数
    domains.forEach(domain => {
        const expiryDate = new Date(domain.expiryDate);
        const today = new Date();
        domain.daysLeft = Math.ceil((expiryDate - today) / (1000 * 60 * 60 * 24));
        
        // 调试输出价格信息
        if (domain.price) {
            console.log('域名 ' + domain.name + ' 的价格:', domain.price);
        } else {
            console.log('域名 ' + domain.name + ' 没有价格信息');
        }
    });
    
    // 按照指定字段和顺序排序
    sortDomains(domains, currentSortField, currentSortOrder);
    
    // 为了保持每列的独立性，我们先对域名进行分组
    const columnDomains = [[], [], []];
    
    // 将域名分配到不同的列中
    domains.forEach((domain, index) => {
        const columnIndex = index % 3;
        columnDomains[columnIndex].push(domain);
    });
    
    // 分别处理每一列的域名
    columnDomains.forEach((domainGroup, columnIndex) => {
        domainGroup.forEach(domain => {
        const expiryDate = new Date(domain.expiryDate);
        const today = new Date();
        const daysLeft = domain.daysLeft;
        
        // 确保通知设置存在
        if (!domain.notifySettings) {
            domain.notifySettings = { useGlobalSettings: true, enabled: true, notifyDays: 30 };
        }
        
        // 获取该域名的通知设置
        const notifySettings = domain.notifySettings;
        const notifyDays = notifySettings.useGlobalSettings ? globalNotifyDays : notifySettings.notifyDays;
        
        // 状态标签逻辑（与原来保持一致）
        let statusClass = 'safe';
        let statusText = '<i class="iconfont icon-circle-check"></i> 正常';
        let statusBadge = 'success';
        
        // 进度条颜色逻辑（先初始化，后面根据百分比设置）
        let progressColor = 'rgba(0, 255, 76, 0.9)'; // 默认绿色
        
        // 设置状态标签
        if (daysLeft <= 0) {
            statusClass = 'expired';
            statusText = '<i class="iconfont icon-triangle-exclamation"></i> 已过期';
            statusBadge = 'danger';
        } else if (daysLeft <= 20) {  // 修改为固定20天，按需求调整
            statusClass = 'warning';
            statusText = '<i class="iconfont icon-bullhorn"></i> 即将到期';
            statusBadge = 'warning';
        }
        
        // 进度条颜色将在计算百分比后设置
        
        // 计算域名有效期的百分比进度
        let totalDays = 0;
        let progressPercent = 0;
        
        // 获取域名的续期周期设置，如果没有则使用默认值（1年）
        let cycleDays = 365; // 默认为1年
        
        if (domain.renewCycle) {
            // 根据续期周期单位计算天数
            switch(domain.renewCycle.unit) {
                case 'year':
                    cycleDays = domain.renewCycle.value * 365;
                    break;
                case 'month':
                    // 更精确地计算月份的实际天数
                    if (domain.renewCycle.value === 1) {
                        // 对于1个月的情况，计算下个月的同一天到这个月的同一天之间的实际天数
                        const currentDate = new Date(domain.expiryDate);
                        const nextMonth = new Date(currentDate);
                        nextMonth.setMonth(nextMonth.getMonth() + 1);
                        cycleDays = Math.round((nextMonth - currentDate) / (1000 * 60 * 60 * 24));
                    } else {
                        // 对于多个月的情况，计算每个月的实际天数
                        const currentDate = new Date(domain.expiryDate);
                        const futureDate = new Date(currentDate);
                        futureDate.setMonth(futureDate.getMonth() + domain.renewCycle.value);
                        cycleDays = Math.round((futureDate - currentDate) / (1000 * 60 * 60 * 24));
                    }
                    break;
                case 'day':
                    cycleDays = domain.renewCycle.value;
                    break;
                default:
                    cycleDays = 365;
            }
        }
        
        // 简化进度条计算逻辑
        if (daysLeft <= 0) {
            // 已过期域名，但如果有lastRenewed字段，说明已续期
            if (domain.lastRenewed) {
                // 计算剩余天数占续费周期的百分比
                const renewedDate = new Date(domain.lastRenewed);
                const expiryDate = new Date(domain.expiryDate);
                const newDaysLeft = Math.ceil((expiryDate - today) / (1000 * 60 * 60 * 24));
                
                if (newDaysLeft >= cycleDays) {
                    progressPercent = 100;
                } else {
                    // 使用精确计算，不进行四舍五入，保留整数部分
                    progressPercent = Math.floor((newDaysLeft / cycleDays) * 100);
                }
            } else {
                progressPercent = 0;
            }
        } else {
            // 未过期域名
            if (daysLeft >= cycleDays) {
                progressPercent = 100;
            } else {
                // 使用精确计算，不进行四舍五入，保留整数部分
                progressPercent = Math.floor((daysLeft / cycleDays) * 100);
            }
        }
        
        // 确保进度百分比在0-100范围内
        if (progressPercent < 0) progressPercent = 0;
        if (progressPercent > 100) progressPercent = 100;
        
        // 根据百分比设置进度条颜色
        if (progressPercent < 10) {
            progressColor = 'rgba(231, 18, 64, 0.9)'; // 小于10%显示红色
        } else if (progressPercent < 30) {
            progressColor = 'rgba(255, 208, 0, 0.9)'; // 10%-30%显示黄色
        } else {
            progressColor = 'rgba(0, 255, 76, 0.9)'; // 大于30%显示绿色
        }
        
        // 创建圆环进度条样式
        let progressCircleHtml = '';
        
        // 使用SVG实现圆环进度条
        const radius = 28; // 略小的圆环半径，确保不会太接近边缘
        const circumference = 2 * Math.PI * radius; // 圆环周长
        const offset = circumference - (progressPercent / 100) * circumference; // 计算偏移量
        
        // 创建SVG圆环进度条，增加SVG尺寸
        const svgSize = 65; // SVG容器大小
        const svgCenter = svgSize / 2; // 居中
        
        // SVG圆环和百分比分开处理
        const percentText = progressPercent + '%';
        
        if (daysLeft <= 0) {
            // 已过期域名显示简化的进度条，但保留0%文本
            progressCircleHtml = 
                '<div style="position:relative; width:' + svgSize + 'px; height:' + svgSize + 'px;">' +
                '<svg class="progress-ring" width="' + svgSize + '" height="' + svgSize + '" viewBox="0 0 ' + svgSize + ' ' + svgSize + '">' +
                '<circle class="progress-ring-circle-bg" stroke="#f5f5f5" stroke-width="6" fill="transparent" r="' + radius + '" cx="' + svgCenter + '" cy="' + svgCenter + '"/>' +
                '</svg>' +
                '<div style="position:absolute; top:0; left:0; right:0; bottom:0; display:flex; align-items:center; justify-content:center; z-index:9999;">' +
                '<span class="progress-percent-text">0%</span>' +
                '</div>' +
                '</div>';
        } else {
            // 正常域名显示完整进度条
            progressCircleHtml = 
                '<div style="position:relative; width:' + svgSize + 'px; height:' + svgSize + 'px;">' +
                '<svg class="progress-ring" width="' + svgSize + '" height="' + svgSize + '" viewBox="0 0 ' + svgSize + ' ' + svgSize + '">' +
                '<circle class="progress-ring-circle-bg" stroke="#f5f5f5" stroke-width="6" fill="transparent" r="' + radius + '" cx="' + svgCenter + '" cy="' + svgCenter + '"/>' +
                '<circle class="progress-ring-circle" stroke="' + progressColor + '" stroke-width="6" fill="transparent" ' +
                'stroke-dasharray="' + circumference + ' ' + circumference + '" ' +
                'style="stroke-dashoffset:' + offset + 'px;" ' +
                'r="' + radius + '" cx="' + svgCenter + '" cy="' + svgCenter + '"/>' +
                '</svg>' +
                '<div style="position:absolute; top:0; left:0; right:0; bottom:0; display:flex; align-items:center; justify-content:center; z-index:9999;">' +
                '<span class="progress-percent-text">' + percentText + '</span>' +
                '</div>' +
                '</div>';
        }
        
        // 创建卡片容器
        const domainCard = document.createElement('div');
        domainCard.className = 'mb-2'; // 进一步减小卡片间距
        // 准备通知信息和上次续期信息
        let infoHtml = '';
        
        // 添加自定义通知信息
        if (!notifySettings.useGlobalSettings) {
            infoHtml += '<small class="text-white d-inline-block me-3">' + 
                (notifySettings.enabled ? '自定义通知: ' + notifySettings.notifyDays + '天' : '通知已禁用') + 
                '</small>';
        }
        
        // 添加上次续期信息
        if (domain.lastRenewed) {
            infoHtml += '<small class="text-white d-inline-block">上次续期: ' + formatDate(domain.lastRenewed) + '</small>';
        }
        
        // 续期链接已整合到按钮行中，不再需要单独的变量
        
        const cardHtml = '<div class="card domain-card ' + statusClass + ' mb-2">' +
            '<div class="card-header">' +
            '<span class="status-dot ' + statusClass + '"></span>' +
            '<div class="domain-header">' +
            '<h5 class="mb-0"><strong>' + domain.name + '</strong></h5>' +
            (domain.registrar ? '<div class="domain-meta">注册商: ' + domain.registrar + '</div>' : '') +
            '</div>' +
            '<div class="domain-status">' +
            '<span class="badge bg-' + statusBadge + '">' + statusText + '</span>' +
            '<button class="btn btn-sm btn-link toggle-details collapsed" data-bs-toggle="collapse" data-bs-target="#details-' + domain.id + '" aria-expanded="false" aria-controls="details-' + domain.id + '">' +
            '<span class="toggle-icon-container">' +
            '<i class="iconfont icon-angle-down toggle-icon"></i>' +
            '</span>' +
            '</button>' +
            '</div>' +
            '</div>' +
            '<div class="collapse" id="details-' + domain.id + '">' +
            '<div class="card-body pb-2">' +
            '<div class="d-flex justify-content-between align-items-start mb-2">' +
            '<div class="flex-grow-1">' +
            (domain.registrationDate ? '<p class="card-text mb-1"><i class="iconfont icon-calendar-days"></i><strong>注册时间:</strong>' + formatDate(domain.registrationDate) + '</p>' : '') +
            '<p class="card-text mb-1"><i class="iconfont icon-rili"></i><strong>到期日期:</strong>' + formatDate(domain.expiryDate) + '</p>' +
            '<p class="card-text mb-1"><i class="iconfont icon-repeat"></i><strong>续期周期:</strong>' + 
            (domain.renewCycle ? domain.renewCycle.value + ' ' + 
            (domain.renewCycle.unit === 'year' ? '年' : 
             domain.renewCycle.unit === 'month' ? '月' : '天') : '1 年') + 
            (function() {
                // 调试输出
                console.log('渲染卡片 ' + domain.name + ' 的价格信息:', domain.price);
                
                if (domain.price) {
                    return ' <span class="text-white-50">(' + domain.price.currency + domain.price.value + 
                    '/' + (domain.price.unit === 'year' ? '年' : 
                           domain.price.unit === 'month' ? '月' : '日') + 
                    ')</span>';
                } else {
                    return '';
                }
            })() + '</p>' +
            '<p class="card-text mb-0"><i class="iconfont icon-hourglass-start"></i><strong>剩余天数:</strong>' + (daysLeft > 0 ? daysLeft + ' 天 <span class="text-white-50">(' + formatDaysToYMD(daysLeft) + ')</span>' : '已过期') + '</p>' +
            '</div>' +
            '<div class="progress-circle-container">' +
            '<div class="progress-circle">' +
            progressCircleHtml +
            '</div>' +
            '</div>' +
            '</div>' +
            (infoHtml ? '<div class="domain-info mb-2">' + infoHtml + '</div>' : '') +
            '<div class="domain-actions">' +
            '<!-- 编辑按钮 -->' +
            '<button class="btn btn-sm btn-primary edit-domain" data-id="' + domain.id + '" title="编辑域名"><i class="iconfont icon-pencil"></i> 编辑</button>' +
            '<!-- 续期按钮 -->' +
            '<button class="btn btn-sm btn-success renew-domain" data-id="' + domain.id + '" data-name="' + domain.name + '" data-expiry="' + domain.expiryDate + '" title="续期域名"><i class="iconfont icon-arrows-rotate"></i> 续期</button>' +
            '<!-- 测试按钮 -->' +
            '<button class="btn btn-sm btn-info test-domain-notify" data-id="' + domain.id + '" title="测试通知"><i class="iconfont icon-paper-plane"></i> 测试</button>' +
            '<!-- 续期链接按钮 -->' +
            (domain.renewLink ? 
            '<a href="' + domain.renewLink + '" target="_blank" class="btn btn-sm btn-warning" title="前往续期页面"><i class="iconfont icon-link"></i> 链接</a>' : 
            '<button class="btn btn-sm btn-secondary" disabled title="未设置续期链接"><i class="iconfont icon-link"></i> 链接</button>') +
            '<!-- 删除按钮 -->' +
            '<button class="btn btn-sm btn-danger delete-domain" data-id="' + domain.id + '" data-name="' + domain.name + '" title="删除域名"><i class="iconfont icon-shanchu"></i> 删除</button>' +
            '</div>' +
            '</div>' +
            '</div>' +
            '</div>';
        domainCard.innerHTML = cardHtml;
        
        // 将卡片添加到对应的列中
        columns[columnIndex].appendChild(domainCard);
        });
    });
    
    // 添加事件监听器
    document.querySelectorAll('.edit-domain').forEach(button => {
        button.addEventListener('click', () => editDomain(button.dataset.id));
    });
    
    document.querySelectorAll('.delete-domain').forEach(button => {
        button.addEventListener('click', () => showDeleteModal(button.dataset.id, button.dataset.name));
    });
    
    document.querySelectorAll('.renew-domain').forEach(button => {
        button.addEventListener('click', () => showRenewModal(button.dataset.id, button.dataset.name, button.dataset.expiry));
    });
    
    // 添加测试通知按钮的事件监听器
    document.querySelectorAll('.test-domain-notify').forEach(button => {
        button.addEventListener('click', () => testDomainNotification(button.dataset.id));
    });
    
            // 添加下拉按钮的事件监听器
    document.querySelectorAll('.toggle-details').forEach(button => {
        // 不需要额外的JavaScript处理，CSS transition会自动处理动画
        button.addEventListener('click', function(e) {
            // 如果当前是全部展开或全部折叠模式，点击切换按钮会切换到自动折叠模式
            if (viewMode !== 'auto-collapse') {
                // 先阻止默认的bootstrap折叠/展开行为
                e.preventDefault();
                e.stopPropagation();
                
                // 切换到自动折叠模式
                viewMode = 'auto-collapse';
                
                // 更新视图按钮文本
                document.getElementById('viewStyleDropdown').innerHTML = 
                    '<i class="iconfont icon-eye"></i> <span style="color: white;">列表样式</span>';
                
                // 获取当前按钮对应的卡片详情
                const collapseTarget = document.querySelector(button.getAttribute('data-bs-target'));
                
                // 折叠所有其他卡片
                document.querySelectorAll('.collapse.show').forEach(detail => {
                    if (detail !== collapseTarget) {
                        bootstrap.Collapse.getInstance(detail)?.hide();
                    }
                });
                
                // 切换当前卡片的状态
                const collapseInstance = bootstrap.Collapse.getInstance(collapseTarget);
                if (collapseInstance) {
                    if (collapseTarget.classList.contains('show')) {
                        collapseInstance.hide();
                    } else {
                        collapseInstance.show();
                    }
                }
            }
            // 在自动折叠模式下，使用默认的bootstrap行为
        });
    });
    
    // 添加点击空白处关闭已展开卡片的功能（仅在自动折叠模式下有效）
    document.addEventListener('click', function(event) {
        // 只在自动折叠模式下处理
        if (viewMode === 'auto-collapse') {
            // 检查点击的元素是否在卡片内部
            const isClickInsideCard = event.target.closest('.domain-card');
            const isClickOnToggleButton = event.target.closest('.toggle-details');
            
            // 如果点击不在卡片内部或不是点击了切换按钮
            if (!isClickInsideCard || isClickOnToggleButton) {
                return;
            }
            
            // 获取所有已展开的卡片详情
            const expandedDetails = document.querySelectorAll('.collapse.show');
            
            // 获取当前点击的卡片中的详情元素
            const currentCardDetails = isClickInsideCard ? isClickInsideCard.querySelector('.collapse') : null;
            
            // 关闭所有不是当前点击卡片的已展开详情
            expandedDetails.forEach(detail => {
                if (detail !== currentCardDetails) {
                    // 使用Bootstrap的collapse API关闭
                    bootstrap.Collapse.getInstance(detail)?.hide();
                }
            });
        }
    });
    
    // 点击页面空白处关闭所有展开的卡片（仅在自动折叠模式下有效）
    document.addEventListener('click', function(event) {
        // 只在自动折叠模式下处理
        if (viewMode === 'auto-collapse') {
            // 如果点击的是页面空白处（不在任何卡片内）
            if (!event.target.closest('.domain-card') && !event.target.closest('.modal')) {
                // 获取所有已展开的卡片详情
                const expandedDetails = document.querySelectorAll('.collapse.show');
                
                // 关闭所有已展开的详情
                expandedDetails.forEach(detail => {
                    bootstrap.Collapse.getInstance(detail)?.hide();
                });
            }
        }
    });
    
    // 处理视图模式更改
    function handleViewModeChange() {
        // 获取所有卡片的详情区域
        const allCardDetails = document.querySelectorAll('.domain-card .collapse');
        
        // 根据当前视图模式处理
        switch (viewMode) {
            case 'expand-all':
                // 展开所有卡片 - 使用更直接的方法
                allCardDetails.forEach(detail => {
                    // 手动添加show类
                    detail.classList.add('show');
                    
                    // 查找对应的切换按钮
                    const detailId = detail.id;
                    const toggleButton = document.querySelector('[data-bs-target="#' + detailId + '"]');
                    if (toggleButton) {
                        toggleButton.classList.remove('collapsed');
                        toggleButton.setAttribute('aria-expanded', 'true');
                    }
                    
                    // 处理父元素
                    const parentCard = detail.closest('.domain-card');
                    if (parentCard) {
                        parentCard.classList.add('expanded');
                    }
                });
                break;
                
            case 'collapse-all':
                // 折叠所有卡片 - 使用更直接的方法
                allCardDetails.forEach(detail => {
                    // 手动移除show类
                    detail.classList.remove('show');
                    
                    // 查找对应的切换按钮
                    const detailId = detail.id;
                    const toggleButton = document.querySelector('[data-bs-target="#' + detailId + '"]');
                    if (toggleButton) {
                        toggleButton.classList.add('collapsed');
                        toggleButton.setAttribute('aria-expanded', 'false');
                    }
                    
                    // 处理父元素
                    const parentCard = detail.closest('.domain-card');
                    if (parentCard) {
                        parentCard.classList.remove('expanded');
                    }
                });
                break;
                
            case 'auto-collapse':
                // 默认全部折叠，然后用户可以手动展开/折叠
                allCardDetails.forEach(detail => {
                    // 手动移除show类
                    detail.classList.remove('show');
                    
                    // 查找对应的切换按钮
                    const detailId = detail.id;
                    const toggleButton = document.querySelector('[data-bs-target="#' + detailId + '"]');
                    if (toggleButton) {
                        toggleButton.classList.add('collapsed');
                        toggleButton.setAttribute('aria-expanded', 'false');
                    }
                    
                    // 处理父元素
                    const parentCard = detail.closest('.domain-card');
                    if (parentCard) {
                        parentCard.classList.remove('expanded');
                    }
                });
                break;
        }
    }
    
    // 确保所有卡片的collapse实例都被正确初始化
    function initializeAllCollapses() {
        document.querySelectorAll('.domain-card .collapse').forEach(detail => {
            // 初始化Collapse实例
            if (!bootstrap.Collapse.getInstance(detail)) {
                new bootstrap.Collapse(detail, {
                    toggle: false
                });
            }
        });
    }

    // 确保所有卡片的collapse实例都被正确初始化
    initializeAllCollapses();
    
    // 应用当前视图模式
    handleViewModeChange();

    /* 
    // 示例：如何将按钮改为纯图标
    // 将以下代码添加到renderDomainList函数的最后，或者修改上面的HTML生成代码

    // 1. 将按钮文字替换为纯图标
    const domainActionButtons = document.querySelectorAll('.domain-actions .btn');
    domainActionButtons.forEach(button => {
        // 保留图标，移除文字
        const icon = button.querySelector('.iconfont');
        if (icon) {
            button.innerHTML = '';
            button.appendChild(icon);
            button.classList.add('btn-icon-only');
        }
    });

    // 2. 修改续期链接为纯图标
    const renewLinks = document.querySelectorAll('.renew-link-btn');
    renewLinks.forEach(link => {
        const icon = link.querySelector('.iconfont');
        if (icon) {
            link.innerHTML = '';
            link.appendChild(icon);
            link.classList.add('link-icon-only');
            // 可以添加额外的样式
            link.style.width = '40px';
            link.style.height = '40px';
            link.style.borderRadius = '50%';
            link.style.display = 'flex';
            link.style.alignItems = 'center';
            link.style.justifyContent = 'center';
            link.style.margin = '0 auto';
        }
    });

    // 3. 修改未设置续期链接提示为纯图标
    const disabledLinks = document.querySelectorAll('.disabled-link-btn');
    disabledLinks.forEach(link => {
        const icon = link.querySelector('.iconfont');
        if (icon) {
            link.innerHTML = '';
            link.appendChild(icon);
            link.classList.add('link-icon-only');
            // 可以添加额外的样式
            link.style.width = '40px';
            link.style.height = '40px';
            link.style.borderRadius = '50%';
            link.style.display = 'flex';
            link.style.alignItems = 'center';
            link.style.justifyContent = 'center';
            link.style.margin = '0 auto';
        }
    });
    */
}
        
        // 保存域名
async function saveDomain() {
    const domainId = document.getElementById('domainId').value;
    const name = document.getElementById('domainName').value;
    const expiryDate = document.getElementById('expiryDate').value;
    const registrationDate = document.getElementById('registrationDate').value;
    const registrar = document.getElementById('registrar').value;
    const renewLink = document.getElementById('renewLink').value;
    
    // 获取续期周期设置
    const renewCycleValue = parseInt(document.getElementById('renewCycleValue').value) || 1;
    const renewCycleUnit = document.getElementById('renewCycleUnit').value;
    
    // 获取价格设置
    const priceValue = document.getElementById('priceValue').value ? parseFloat(document.getElementById('priceValue').value) : null;
    const priceCurrency = document.getElementById('priceCurrency').value;
    const priceUnit = document.getElementById('priceUnit').value;
    
    // 获取上次续期时间，如果用户清除了则设为null
    const lastRenewed = document.getElementById('lastRenewed').value || null;
    
    // 获取通知设置
    const useGlobalSettings = document.getElementById('useGlobalSettings').checked;
    const notifyEnabled = document.getElementById('notifyEnabled').checked;
    const notifyDays = parseInt(document.getElementById('domainNotifyDays').value) || 30;
    
    if (!name || !expiryDate) {
        showAlert('danger', '域名和到期日期为必填项');
        return;
    }
    
    // 确保通知设置字段存在且正确
    const notifySettings = {
        useGlobalSettings: useGlobalSettings,
        enabled: notifyEnabled,
        notifyDays: notifyDays
    };
    
    // 构建价格对象
    const priceObj = priceValue !== null ? {
        value: priceValue,
        currency: priceCurrency,
        unit: priceUnit
    } : null;
    
    // 调试输出
    console.log('价格值:', priceValue);
    console.log('货币单位:', priceCurrency);
    console.log('价格周期:', priceUnit);
    console.log('价格对象:', priceObj);
    
    const domainData = {
        name,
        expiryDate,
        registrationDate,
        registrar,
        renewLink,
        lastRenewed,
        renewCycle: {
            value: renewCycleValue,
            unit: renewCycleUnit
        },
        price: priceObj,
        notifySettings: notifySettings
    };
            
            try {
                let response;
                if (domainId) {
                    // 更新现有域名
                    domainData.id = domainId;
                    response = await fetch('/api/domains/' + domainId, {
                        headers: { 'Content-Type': 'application/json' },
                        method: 'PUT',
                        body: JSON.stringify(domainData)
                    });
                } else {
                    // 添加新域名
                    response = await fetch('/api/domains', {
                        headers: { 'Content-Type': 'application/json' },
                        method: 'POST',
                        body: JSON.stringify(domainData)
                    });
                }
                
                if (!response.ok) throw new Error('保存域名失败');
                
                // 输出调试信息
                console.log('发送的数据:', domainData);
                
                // 关闭模态框并重新加载域名列表
                bootstrap.Modal.getInstance(document.getElementById('addDomainModal')).hide();
                resetForm();
                await loadDomains();
                showAlert('success', domainId ? '域名更新成功' : '域名添加成功');
            } catch (error) {
                showAlert('danger', '保存域名失败: ' + error.message);
            }
        }
        
        // 编辑域名
        function editDomain(id) {
            const domain = domains.find(d => d.id === id);
            if (!domain) return;
            
            document.getElementById('domainId').value = domain.id;
            document.getElementById('domainName').value = domain.name;
            document.getElementById('expiryDate').value = domain.expiryDate;
            document.getElementById('registrationDate').value = domain.registrationDate || '';
            document.getElementById('registrar').value = domain.registrar || '';
            document.getElementById('renewLink').value = domain.renewLink || '';
            
            // 设置续期周期
            if (domain.renewCycle) {
                document.getElementById('renewCycleValue').value = domain.renewCycle.value || 1;
                document.getElementById('renewCycleUnit').value = domain.renewCycle.unit || 'year';
            } else {
                document.getElementById('renewCycleValue').value = 1;
                document.getElementById('renewCycleUnit').value = 'year';
            }
            
            // 设置价格
            if (domain.price) {
                document.getElementById('priceValue').value = domain.price.value;
                document.getElementById('priceCurrency').value = domain.price.currency || '¥';
                document.getElementById('priceUnit').value = domain.price.unit || 'year';
            } else {
                document.getElementById('priceValue').value = '';
                document.getElementById('priceCurrency').value = '¥';
                document.getElementById('priceUnit').value = 'year';
            }
            
            // 显示上次续期时间（如果有）
            const lastRenewedContainer = document.getElementById('lastRenewedContainer');
            const lastRenewedDisplay = document.getElementById('lastRenewedDisplay');
            const lastRenewed = document.getElementById('lastRenewed');
            
            if (domain.lastRenewed) {
                lastRenewedContainer.style.display = 'block';
                lastRenewedDisplay.textContent = formatDate(domain.lastRenewed);
                lastRenewed.value = domain.lastRenewed;
            } else {
                lastRenewedContainer.style.display = 'none';
                lastRenewedDisplay.textContent = '';
                lastRenewed.value = '';
            }
            
            // 设置通知选项
            const notifySettings = domain.notifySettings || { useGlobalSettings: true, enabled: true, notifyDays: 30 };
            document.getElementById('useGlobalSettings').checked = notifySettings.useGlobalSettings;
            document.getElementById('notifyEnabled').checked = notifySettings.enabled;
            document.getElementById('domainNotifyDays').value = notifySettings.notifyDays || 30;
            document.getElementById('domainNotifySettings').style.display = notifySettings.useGlobalSettings ? 'none' : 'block';
            
            document.querySelector('#addDomainModal .modal-title').textContent = '编辑域名';
            const modal = new bootstrap.Modal(document.getElementById('addDomainModal'));
            modal.show();
        }
        
        // 显示删除确认模态框
        function showDeleteModal(id, name) {
            currentDomainId = id;
            document.getElementById('deleteModalDomainName').textContent = name;
            const modal = new bootstrap.Modal(document.getElementById('deleteDomainModal'));
            modal.show();
        }
        
        // 删除域名
        async function deleteDomain() {
            if (!currentDomainId) return;
            
            try {
                const response = await fetch('/api/domains/' + currentDomainId, {
                    method: 'DELETE'
                });
                
                if (!response.ok) throw new Error('删除域名失败');
                
                // 关闭模态框并重新加载域名列表
                bootstrap.Modal.getInstance(document.getElementById('deleteDomainModal')).hide();
                currentDomainId = null;
                await loadDomains();
                showAlert('success', '域名删除成功');
            } catch (error) {
                showAlert('danger', '删除域名失败: ' + error.message);
            }
        }
        
        // 显示续期模态框
        function showRenewModal(id, name, expiryDate) {
            currentDomainId = id;
            document.getElementById('renewModalDomainName').textContent = name;
            
            // 获取域名的续期周期设置
            const domain = domains.find(d => d.id === id);
            if (domain && domain.renewCycle) {
                document.getElementById('renewPeriodValue').value = domain.renewCycle.value;
                document.getElementById('renewPeriodUnit').value = domain.renewCycle.unit;
            } else {
                document.getElementById('renewPeriodValue').value = 1;
                document.getElementById('renewPeriodUnit').value = 'year';
            }
            
            // 计算新的到期日期
            updateNewExpiryDate();
            
            const modal = new bootstrap.Modal(document.getElementById('renewDomainModal'));
            modal.show();
        }
        
        // 更新新到期日期
        function updateNewExpiryDate() {
            const domain = domains.find(d => d.id === currentDomainId);
            if (!domain) return;
            
            const renewValue = parseInt(document.getElementById('renewPeriodValue').value) || 1;
            const renewUnit = document.getElementById('renewPeriodUnit').value;
            
            // 无论域名是否过期，都从原先的到期日期开始计算
            const expiryDate = new Date(domain.expiryDate);
            const newExpiryDate = new Date(expiryDate);
            
            // 根据选择的单位添加时间
            switch(renewUnit) {
                case 'year':
                    newExpiryDate.setFullYear(expiryDate.getFullYear() + renewValue);
                    break;
                case 'month':
                    newExpiryDate.setMonth(expiryDate.getMonth() + renewValue);
                    break;
                case 'day':
                    newExpiryDate.setDate(expiryDate.getDate() + renewValue);
                    break;
            }
            
            document.getElementById('newExpiryDate').value = newExpiryDate.toISOString().split('T')[0];
        }
        
        // 续期域名
        async function renewDomain() {
            if (!currentDomainId) return;
            
            const renewValue = parseInt(document.getElementById('renewPeriodValue').value) || 1;
            const renewUnit = document.getElementById('renewPeriodUnit').value;
            const newExpiryDate = document.getElementById('newExpiryDate').value;
            
            try {
                const response = await fetch('/api/domains/' + currentDomainId + '/renew', {
                    headers: { 'Content-Type': 'application/json' },
                    method: 'POST',
                    body: JSON.stringify({ 
                        value: renewValue, 
                        unit: renewUnit, 
                        newExpiryDate 
                    })
                });
                
                if (!response.ok) throw new Error('域名续期失败');
                
                // 关闭模态框并重新加载域名列表
                bootstrap.Modal.getInstance(document.getElementById('renewDomainModal')).hide();
                currentDomainId = null;
                await loadDomains();
                showAlert('success', '域名续期成功');
            } catch (error) {
                showAlert('danger', '域名续期失败: ' + error.message);
            }
        }
        
        // 重置表单
        function resetForm() {
            document.getElementById('domainId').value = '';
            document.getElementById('domainName').value = '';
            document.getElementById('expiryDate').value = '';
            document.getElementById('registrationDate').value = '';
            document.getElementById('registrar').value = '';
            document.getElementById('renewLink').value = '';
            
            // 重置续期周期设置
            document.getElementById('renewCycleValue').value = '1';
            document.getElementById('renewCycleUnit').value = 'year';
            
            // 重置价格设置
            document.getElementById('priceValue').value = '';
            document.getElementById('priceCurrency').value = '¥';
            document.getElementById('priceUnit').value = 'year';
            
            // 重置上次续期时间
            document.getElementById('lastRenewed').value = '';
            document.getElementById('lastRenewedContainer').style.display = 'none';
            document.getElementById('lastRenewedDisplay').textContent = '';
            document.getElementById('lastRenewedDisplay').classList.remove('text-danger');
            
            // 重置通知设置
            document.getElementById('useGlobalSettings').checked = true;
            document.getElementById('notifyEnabled').checked = true;
            document.getElementById('domainNotifyDays').value = '30';
            document.getElementById('domainNotifySettings').style.display = 'none';
            
            document.querySelector('#addDomainModal .modal-title').textContent = '添加新域名';
        }
        
        // 显示提示信息
function showAlert(type, message) {
    const alertDiv = document.createElement('div');
    alertDiv.className = 'alert alert-' + type + ' alert-dismissible fade show position-fixed top-0 start-50 translate-middle-x mt-3';
    alertDiv.style.zIndex = '9999';
    alertDiv.style.boxShadow = '0 4px 12px rgba(0,0,0,0.15)';
    alertDiv.style.borderRadius = '8px';
    alertDiv.style.minWidth = '300px';
    alertDiv.style.maxWidth = '80%';
    
    // 根据消息类型选择合适的图标
    let iconClass = '';
    switch(type) {
        case 'success':
            iconClass = 'icon-success';
            break;
        case 'danger':
            iconClass = 'icon-error';
            break;
        case 'warning':
            iconClass = 'icon-warning';
            break;
        case 'info':
            iconClass = 'icon-info';
            break;
    }
    
    alertDiv.innerHTML = '<i class="iconfont ' + iconClass + '"></i> ' + message +
        '<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>';
    document.body.appendChild(alertDiv);
    
    // 3秒后自动消失
    setTimeout(() => {
        alertDiv.classList.remove('show');
        setTimeout(() => alertDiv.remove(), 300);
    }, 3000);
}
        
        // 格式化日期
        function formatDate(dateString) {
            const date = new Date(dateString);
            return date.toLocaleDateString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit' });
        }

        // 添加测试单个域名通知的函数
        async function testDomainNotification(domainId) {
            try {
                const response = await fetch('/api/domains/' + domainId + '/test-notify', {
                    method: 'POST'
                });
                
                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.error || '测试失败');
                }
                
                const result = await response.json();
                showAlert('success', '通知测试成功！请检查Telegram是否收到消息');
            } catch (error) {
                showAlert('danger', '测试通知失败: ' + error.message);
            }
        }

        // 按照指定字段和顺序排序域名
        function sortDomains(domains, field, order) {
            domains.sort((a, b) => {
                let valueA, valueB;
                
                // 根据字段提取排序值
                switch (field) {
                    case 'name':
                        valueA = a.name.toLowerCase();
                        valueB = b.name.toLowerCase();
                        break;
                    case 'registrar':
                        valueA = (a.registrar || '').toLowerCase();
                        valueB = (b.registrar || '').toLowerCase();
                        break;
                    case 'expiryDate':
                        valueA = new Date(a.expiryDate).getTime();
                        valueB = new Date(b.expiryDate).getTime();
                        break;
                    case 'daysLeft':
                        valueA = a.daysLeft;
                        valueB = b.daysLeft;
                        break;
                    case 'notifyDays':
                        const notifySettingsA = a.notifySettings || { useGlobalSettings: true, notifyDays: 30 };
                        const notifySettingsB = b.notifySettings || { useGlobalSettings: true, notifyDays: 30 };
                        valueA = notifySettingsA.useGlobalSettings ? (telegramConfig.notifyDays || 30) : notifySettingsA.notifyDays;
                        valueB = notifySettingsB.useGlobalSettings ? (telegramConfig.notifyDays || 30) : notifySettingsB.notifyDays;
                        break;
                    default:
                        valueA = a.daysLeft;
                        valueB = b.daysLeft;
                }
                
                // 根据排序顺序返回比较结果
                if (order === 'asc') {
                    return valueA > valueB ? 1 : valueA < valueB ? -1 : 0;
                } else {
                    return valueA < valueB ? 1 : valueA > valueB ? -1 : 0;
                }
            });
        }
    </script>
</body>
</html>
`;

// 处理请求
async function handleRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname;
  
  // 获取标题
  // 优先级：环境变量 > 代码变量 > 默认值'域名到期监控'
  let siteTitle;
  if (typeof TITLE !== 'undefined' && TITLE !== '') {
    // 如果环境变量中有设置，使用环境变量
    siteTitle = TITLE;
  } else if (DEFAULT_TITLE !== '') {
    // 如果环境变量中没有，但代码变量有设置，使用代码变量
    siteTitle = DEFAULT_TITLE;
  } else {
    // 如果环境变量和代码变量都没有设置，使用默认值
    siteTitle = '域名到期监控';
  }

  // 获取正确的密码
  // 优先级：环境变量 > 代码变量 > 默认密码'domain'
  let correctPassword;
  
  // 检查是否有环境变量TOKEN
  if (typeof TOKEN !== 'undefined' && TOKEN !== '') {
    // 使用环境变量中的TOKEN
    correctPassword = TOKEN;
  } else if (DEFAULT_TOKEN !== '') {
    // 使用代码中定义的DEFAULT_TOKEN
    correctPassword = DEFAULT_TOKEN;
  } else {
    // 如果环境变量和代码中都没有设置，使用默认密码
    correctPassword = 'domain';
  }

  // 检查是否已经登录（通过cookie）
  const cookieHeader = request.headers.get('Cookie') || '';
  const isAuthenticated = cookieHeader.includes('auth=true');
  
  // 处理登录POST请求
  if (path === '/login' && request.method === 'POST') {
    try {
      const requestData = await request.json();
      const submittedPassword = requestData.password;
      
      if (submittedPassword === correctPassword) {
        // 密码正确，设置cookie并重定向到dashboard
        return new Response(JSON.stringify({ success: true }), {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            'Set-Cookie': 'auth=true; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400', // 24小时过期
          },
        });
      } else {
        // 密码错误
        return new Response(JSON.stringify({ success: false, error: '密码错误' }), {
          status: 401,
          headers: {
            'Content-Type': 'application/json',
          },
        });
      }
    } catch (error) {
      return new Response(JSON.stringify({ success: false, error: '请求格式错误' }), {
        status: 400,
        headers: {
          'Content-Type': 'application/json',
        },
      });
    }
  }
  
  // 处理dashboard页面请求
  if (path === '/dashboard') {
    if (isAuthenticated) {
      // 已登录，显示主页面
      const htmlContent = getHTMLContent(siteTitle);
      const response = new Response(htmlContent, {
        headers: {
          'Content-Type': 'text/html;charset=UTF-8',
        },
      });
      
      return await addFooterToResponse(response);
    } else {
      // 未登录，重定向到登录页面
      return Response.redirect(url.origin, 302);
    }
  }
  
  // 登出功能
  if (path === '/logout') {
    return new Response('登出成功', {
      status: 302,
      headers: {
        'Location': '/',
        'Set-Cookie': 'auth=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0', // 清除cookie
      },
    });
  }
  
  // 根路径或任何其他路径（除了/api和/dashboard）都显示登录页面
  if (path === '/' || (!path.startsWith('/api/') && path !== '/dashboard')) {
    // 如果已登录，重定向到dashboard
    if (isAuthenticated) {
      return Response.redirect(`${url.origin}/dashboard`, 302);
    }
    
    const loginHtml = getLoginHTML(siteTitle);
    return new Response(loginHtml, {
      headers: {
        'Content-Type': 'text/html;charset=UTF-8',
      },
    });
  }
  
  // API 路由处理
  if (path.startsWith('/api/')) {
    // 检查是否已登录
    if (!isAuthenticated) {
      return jsonResponse({ error: '未授权访问', success: false }, 401);
    }
    
    return await handleApiRequest(request);
  }
  
  // 如果都不匹配，返回登录页面
  const loginHtml = getLoginHTML(siteTitle);
  return new Response(loginHtml, {
    headers: {
      'Content-Type': 'text/html;charset=UTF-8',
    },
  });
}



// 处理API请求
async function handleApiRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname;
  
  // 获取所有域名
  if (path === '/api/domains' && request.method === 'GET') {
    try {
      const domains = await getDomains();
      return jsonResponse(domains);
    } catch (error) {
      return jsonResponse({ error: '获取域名列表失败' }, 500);
    }
  }
  
  // 添加新域名
  if (path === '/api/domains' && request.method === 'POST') {
    try {
      const domainData = await request.json();
      const domain = await addDomain(domainData);
      return jsonResponse(domain, 201);
    } catch (error) {
      return jsonResponse({ error: '添加域名失败' }, 400);
    }
  }
  
  // 更新域名
  if (path.match(/^\/api\/domains\/[^\/]+$/) && request.method === 'PUT') {
    const id = path.split('/').pop();
    try {
      const domainData = await request.json();
      const domain = await updateDomain(id, domainData);
      return jsonResponse(domain);
    } catch (error) {
      return jsonResponse({ error: '更新域名失败' }, 400);
    }
  }
  
  // 删除域名
  if (path.match(/^\/api\/domains\/[^\/]+$/) && request.method === 'DELETE') {
    const id = path.split('/').pop();
    try {
      await deleteDomain(id);
      return jsonResponse({ success: true });
    } catch (error) {
      return jsonResponse({ error: '删除域名失败' }, 400);
    }
  }
  
  // 域名续期
  if (path.match(/^\/api\/domains\/[^\/]+\/renew$/) && request.method === 'POST') {
    const id = path.split('/')[3];
    try {
      const renewData = await request.json();
      const domain = await renewDomain(id, renewData);
      return jsonResponse(domain);
    } catch (error) {
      return jsonResponse({ error: '域名续期失败' }, 400);
    }
  }
  
  // 获取Telegram配置
  if (path === '/api/telegram/config' && request.method === 'GET') {
    try {
      const config = await getTelegramConfig();
      return jsonResponse(config);
    } catch (error) {
      return jsonResponse({ error: '获取Telegram配置失败' }, 500);
    }
  }
  
  // 保存Telegram配置
  if (path === '/api/telegram/config' && request.method === 'POST') {
    try {
      const configData = await request.json();
      console.log('保存Telegram配置:', JSON.stringify(configData));
      const config = await saveTelegramConfig(configData);
      console.log('保存成功，返回配置:', JSON.stringify(config));
      return jsonResponse(config);
    } catch (error) {
      console.error('保存Telegram配置失败:', error);
      return jsonResponse({ error: '保存Telegram配置失败: ' + error.message }, 400);
    }
  }
  
  // 测试Telegram通知
  if (path === '/api/telegram/test' && request.method === 'POST') {
    try {
      const result = await testTelegramNotification();
      return jsonResponse(result);
    } catch (error) {
      return jsonResponse({ error: '测试Telegram通知失败: ' + error.message }, 400);
    }
  }

  // 测试单个域名的通知
  if (path.match(/^\/api\/domains\/[^\/]+\/test-notify$/) && request.method === 'POST') {
    const id = path.split('/')[3];
    try {
      const result = await testSingleDomainNotification(id);
      return jsonResponse(result);
    } catch (error) {
      return jsonResponse({ error: '测试通知失败: ' + error.message }, 400);
    }
  }
  
  // 404 - 路由不存在
  return jsonResponse({ error: '未找到请求的资源' }, 404);
}

// 获取所有域名
async function getDomains() {
  const domainsStr = await DOMAIN_MONITOR.get('domains') || '[]';
  return JSON.parse(domainsStr);
}

// 添加新域名
async function addDomain(domainData) {
  const domains = await getDomains();
  
  // 验证域名数据
  if (!domainData.name || !domainData.expiryDate) {
    throw new Error('域名和到期日期为必填项');
  }
  
  // 生成唯一ID
  domainData.id = crypto.randomUUID();
  
  // 添加创建时间
  domainData.createdAt = new Date().toISOString();
  
  // 处理通知设置
  if (!domainData.notifySettings) {
    // 添加默认通知设置
    domainData.notifySettings = {
      useGlobalSettings: true,
      notifyDays: 30,
      enabled: true
    };
  }
  
          // 确保有lastRenewed字段
        if (!domainData.lastRenewed) {
            domainData.lastRenewed = null;
        }
        
        // 添加到列表
        domains.push(domainData);
        
        // 保存到KV
        await DOMAIN_MONITOR.put('domains', JSON.stringify(domains));
        
        return domainData;
}

// 更新域名
async function updateDomain(id, domainData) {
  const domains = await getDomains();
  
  // 查找域名索引
  const index = domains.findIndex(d => d.id === id);
  if (index === -1) {
    throw new Error('域名不存在');
  }
  
  // 验证域名数据
  if (!domainData.name || !domainData.expiryDate) {
    throw new Error('域名和到期日期为必填项');
  }
  
  // 确保通知设置正确
  let notifySettings;
  if (domainData.notifySettings) {
    // 使用提交的通知设置
    notifySettings = domainData.notifySettings;
  } else if (domains[index].notifySettings) {
    // 使用现有的通知设置
    notifySettings = domains[index].notifySettings;
  } else {
    // 创建默认通知设置
    notifySettings = {
      useGlobalSettings: true,
      notifyDays: 30,
      enabled: true
    };
  }
  
  // 更新域名
  domains[index] = {
    ...domains[index],
    name: domainData.name,
    expiryDate: domainData.expiryDate,
    registrationDate: domainData.registrationDate || domains[index].registrationDate,
    registrar: domainData.registrar,
    renewLink: domainData.renewLink || domains[index].renewLink, // 更新续费链接
    renewCycle: domainData.renewCycle || domains[index].renewCycle,
    price: domainData.price !== undefined ? domainData.price : domains[index].price, // 添加价格信息，保留现有价格如果未提供
    lastRenewed: domainData.lastRenewed !== undefined ? domainData.lastRenewed : domains[index].lastRenewed, // 根据用户选择更新续期时间
    notifySettings: notifySettings,
    updatedAt: new Date().toISOString()
  };
  
  // 保存到KV
  await DOMAIN_MONITOR.put('domains', JSON.stringify(domains));
  
  return domains[index];
}

// 删除域名
async function deleteDomain(id) {
  const domains = await getDomains();
  
  // 过滤掉要删除的域名
  const newDomains = domains.filter(d => d.id !== id);
  
  // 如果长度相同，说明没有找到要删除的域名
  if (newDomains.length === domains.length) {
    throw new Error('域名不存在');
  }
  
  // 保存到KV
  await DOMAIN_MONITOR.put('domains', JSON.stringify(newDomains));
  
  return true;
}

// 域名续期
async function renewDomain(id, renewData) {
  const domains = await getDomains();
  
  // 查找域名索引
  const index = domains.findIndex(d => d.id === id);
  if (index === -1) {
    throw new Error('域名不存在');
  }
  
  const now = new Date();
  
      // 更新域名信息中的续期数据
    if (!domains[index].renewCycle) {
        domains[index].renewCycle = {
            value: renewData.value || 1,
            unit: renewData.unit || 'year'
        };
    }
    
    // 如果域名是已过期状态，标记为从当前时间开始的全新计算
    if (new Date(domains[index].expiryDate) < new Date()) {
        domains[index].renewedFromExpired = true;
        domains[index].renewStartDate = now.toISOString(); // 记录续期开始时间（当前时间）
    }
  
  // 更新到期日期和续期记录
  domains[index] = {
    ...domains[index],
    expiryDate: renewData.newExpiryDate,
    updatedAt: now.toISOString(),
    lastRenewed: now.toISOString(), // 记录本次续期时间
    lastRenewPeriod: {
      value: renewData.value,
      unit: renewData.unit
    } // 记录本次续期周期，用于进度条计算
  };
  
  // 保存到KV
  await DOMAIN_MONITOR.put('domains', JSON.stringify(domains));
  
  return domains[index];
}

// 获取Telegram配置
async function getTelegramConfig() {
  const configStr = await DOMAIN_MONITOR.get('telegram_config') || '{}';
  const config = JSON.parse(configStr);
  
  // 检查是否使用环境变量
  // 当环境变量存在且配置中的值为undefined、null或空字符串时，视为使用环境变量
  const tokenFromEnv = typeof TG_TOKEN !== 'undefined' && (
    config.botToken === undefined || 
    config.botToken === null || 
    config.botToken === ''
  );
  
  const chatIdFromEnv = typeof TG_ID !== 'undefined' && (
    config.chatId === undefined || 
    config.chatId === null || 
    config.chatId === ''
  );
  
  // 检查是否使用代码中定义的变量
  const tokenFromCode = !tokenFromEnv && DEFAULT_TG_TOKEN !== '' && (
    config.botToken === undefined || 
    config.botToken === null || 
    config.botToken === ''
  );
  
  const chatIdFromCode = !chatIdFromEnv && DEFAULT_TG_ID !== '' && (
    config.chatId === undefined || 
    config.chatId === null || 
    config.chatId === ''
  );
  
  // 返回完整的配置信息，包括token和chatId
  return {
    enabled: !!config.enabled,
    chatId: chatIdFromEnv || chatIdFromCode ? '' : (config.chatId || ''),
    botToken: tokenFromEnv || tokenFromCode ? '' : (config.botToken || ''), // 如果有环境变量或代码变量，则返回空字符串
    chatIdFromEnv: chatIdFromEnv || chatIdFromCode, // 环境变量或代码中有设置都显示为已配置
    tokenFromEnv: tokenFromEnv || tokenFromCode, // 环境变量或代码中有设置都显示为已配置
    hasToken: tokenFromEnv || tokenFromCode || (config.botToken !== undefined && config.botToken !== null && config.botToken !== ''),
    notifyDays: config.notifyDays || 30,
  };
}

// 保存Telegram配置
async function saveTelegramConfig(configData) {
  // 验证必要的配置 - 只有当启用Telegram通知且环境变量中也没有配置时才需要验证
  if (configData.enabled) {
    // 检查是否可以使用环境变量或用户输入的值
    // 注意：空字符串("")被视为有效的清除操作，不应该抛出错误
    const hasTokenSource = (configData.botToken !== undefined && configData.botToken !== null) || 
                          typeof TG_TOKEN !== 'undefined' || 
                          DEFAULT_TG_TOKEN !== '';
    const hasChatIdSource = (configData.chatId !== undefined && configData.chatId !== null) || 
                           typeof TG_ID !== 'undefined' || 
                           DEFAULT_TG_ID !== '';
    
    if (!hasTokenSource) {
      throw new Error('启用Telegram通知需要提供机器人Token或在环境变量中配置');
    }
    if (!hasChatIdSource) {
      throw new Error('启用Telegram通知需要提供聊天ID或在环境变量中配置');
    }
  }
  
  // 保存配置到KV - 即使值为空也保存，表示用户有意清除值
  const config = {
    enabled: !!configData.enabled,
    botToken: configData.botToken, // 可能为空字符串，表示用户清除了值
    chatId: configData.chatId, // 可能为空字符串，表示用户清除了值
    notifyDays: configData.notifyDays || 30,
  };
  
  await DOMAIN_MONITOR.put('telegram_config', JSON.stringify(config));
  
  // 检查是否使用环境变量
  // 当环境变量存在且配置中的值为undefined、null或空字符串时，视为使用环境变量
  const tokenFromEnv = typeof TG_TOKEN !== 'undefined' && (
    config.botToken === undefined || 
    config.botToken === null || 
    config.botToken === ''
  );
  
  const chatIdFromEnv = typeof TG_ID !== 'undefined' && (
    config.chatId === undefined || 
    config.chatId === null || 
    config.chatId === ''
  );
  
  // 检查是否使用代码中定义的变量
  const tokenFromCode = !tokenFromEnv && DEFAULT_TG_TOKEN !== '' && (
    config.botToken === undefined || 
    config.botToken === null || 
    config.botToken === ''
  );
  
  const chatIdFromCode = !chatIdFromEnv && DEFAULT_TG_ID !== '' && (
    config.chatId === undefined || 
    config.chatId === null || 
    config.chatId === ''
  );
  
  // 返回完整的配置信息，包括token和chatId
  return {
    enabled: config.enabled,
    chatId: chatIdFromEnv || chatIdFromCode ? '' : (config.chatId || ''),
    botToken: tokenFromEnv || tokenFromCode ? '' : (config.botToken || ''), // 如果有环境变量或代码变量，则返回空字符串
    chatIdFromEnv: chatIdFromEnv || chatIdFromCode, // 环境变量或代码中有设置都显示为已配置
    tokenFromEnv: tokenFromEnv || tokenFromCode, // 环境变量或代码中有设置都显示为已配置
    hasToken: tokenFromEnv || tokenFromCode || !!config.botToken,
    notifyDays: config.notifyDays,
  };
}

// 测试Telegram通知
async function testTelegramNotification() {
  const config = await getTelegramConfigWithToken();
  
  if (!config.enabled) {
    throw new Error('Telegram通知未启用');
  }
  
  if (!config.botToken && typeof TG_TOKEN === 'undefined' && DEFAULT_TG_TOKEN === '') {
    throw new Error('未配置Telegram机器人Token');
  }
  
  if (!config.chatId && typeof TG_ID === 'undefined' && DEFAULT_TG_ID === '') {
    throw new Error('未配置Telegram聊天ID');
  }
  
  const message = '这是一条来自域名监控系统的测试通知，如果您收到此消息，表示Telegram通知配置成功！';
  
  const result = await sendTelegramMessage(config, message);
  return { success: true, message: '测试通知已发送' };
}

// 获取完整的Telegram配置（包括token）
async function getTelegramConfigWithToken() {
  const configStr = await DOMAIN_MONITOR.get('telegram_config') || '{}';
  const config = JSON.parse(configStr);
  
  // 如果KV中没有token或chatId，或者是空字符串，但环境变量中有值，则使用环境变量中的值
  if (typeof TG_TOKEN !== 'undefined' && (
      config.botToken === undefined || 
      config.botToken === null || 
      config.botToken === ''
  )) {
    config.botToken = TG_TOKEN;
  }
  
  // 同样处理chatId
  if (typeof TG_ID !== 'undefined' && (
      config.chatId === undefined || 
      config.chatId === null || 
      config.chatId === ''
  )) {
    config.chatId = TG_ID;
  }
  
  // 如果环境变量中没有，但代码中有，则使用代码中的值
  else if (DEFAULT_TG_TOKEN !== '' && (
      config.botToken === undefined || 
      config.botToken === null || 
      config.botToken === ''
  )) {
    config.botToken = DEFAULT_TG_TOKEN;
  }
  
  // 如果环境变量中没有，但代码中有，则使用代码中的值
  else if (DEFAULT_TG_ID !== '' && (
      config.chatId === undefined || 
      config.chatId === null || 
      config.chatId === ''
  )) {
    config.chatId = DEFAULT_TG_ID;
  }
  
  return {
    enabled: !!config.enabled,
    botToken: config.botToken || '',
    chatId: config.chatId || '',
    notifyDays: config.notifyDays || 30,
  };
}

// 发送Telegram消息
async function sendTelegramMessage(config, message) {
  // 优先使用配置中的值，如果没有则使用环境变量或代码中的值
  let botToken = config.botToken;
  let chatId = config.chatId;
  
  // 如果配置中没有值，检查环境变量
  if (!botToken) {
    if (typeof TG_TOKEN !== 'undefined') {
      botToken = TG_TOKEN;
    } else if (DEFAULT_TG_TOKEN !== '') {
      botToken = DEFAULT_TG_TOKEN;
    }
  }
  
  if (!chatId) {
    if (typeof TG_ID !== 'undefined') {
      chatId = TG_ID;
    } else if (DEFAULT_TG_ID !== '') {
      chatId = DEFAULT_TG_ID;
    }
  }
  
  if (!botToken) {
    throw new Error('未配置Telegram机器人Token');
  }
  
  if (!chatId) {
    throw new Error('未配置Telegram聊天ID');
  }
  
  const url = 'https://api.telegram.org/bot' + botToken + '/sendMessage';
  
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      chat_id: chatId,
      text: message,
      parse_mode: 'HTML',
    }),
  });
  
  if (!response.ok) {
    const error = await response.json();
    throw new Error('发送Telegram消息失败: ' + (error.description || '未知错误'));
  }
  
  return await response.json();
}

// 返回JSON响应
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    headers: {
      'Content-Type': 'application/json',
    },
    status,
  });
}

// 设置定时任务，检查即将到期的域名并发送通知
async function checkExpiringDomains() {
  const domains = await getDomains();
  const today = new Date();
  
  // 获取Telegram配置
  const telegramConfig = await getTelegramConfigWithToken();
  const globalNotifyDays = telegramConfig.enabled ? telegramConfig.notifyDays : 30;
  
  // 筛选出即将到期和已过期的域名
  const domainsToNotify = domains.filter(domain => {
    const expiryDate = new Date(domain.expiryDate);
    const daysLeft = Math.ceil((expiryDate - today) / (1000 * 60 * 60 * 24));
    
    // 获取该域名的通知设置
    const notifySettings = domain.notifySettings || { useGlobalSettings: true, enabled: true, notifyDays: 30 };
    
    // 如果使用全局设置，则使用全局通知天数，否则使用域名自己的设置
    const notifyDays = notifySettings.useGlobalSettings ? globalNotifyDays : notifySettings.notifyDays;
    
    // 通知已过期的域名或即将到期的域名
    return notifySettings.enabled && (
      daysLeft <= 0 || // 已过期
      (daysLeft > 0 && daysLeft <= notifyDays) // 即将到期
    );
  });
  
  // 将域名分为已过期和即将到期两组
  const expiredDomains = domainsToNotify.filter(domain => {
    const expiryDate = new Date(domain.expiryDate);
    const daysLeft = Math.ceil((expiryDate - today) / (1000 * 60 * 60 * 24));
    return daysLeft <= 0;
  });
  
  const expiringDomains = domainsToNotify.filter(domain => {
    const expiryDate = new Date(domain.expiryDate);
    const daysLeft = Math.ceil((expiryDate - today) / (1000 * 60 * 60 * 24));
    return daysLeft > 0;
  });
  
  // 如果有即将到期或已过期的域名，发送通知
  if (expiringDomains.length > 0 || expiredDomains.length > 0) {
    console.log('有 ' + expiringDomains.length + ' 个域名即将到期，' + expiredDomains.length + ' 个域名已过期');
    
    // 如果启用了Telegram通知，则发送通知
    if (telegramConfig.enabled && 
        ((telegramConfig.botToken || typeof TG_TOKEN !== 'undefined') && 
         (telegramConfig.chatId || typeof TG_ID !== 'undefined'))) {
      try {
        // 发送即将到期的域名通知
        if (expiringDomains.length > 0) {
          await sendExpiringDomainsNotification(telegramConfig, expiringDomains, false);
        }
        
        // 发送已过期的域名通知
        if (expiredDomains.length > 0) {
          await sendExpiringDomainsNotification(telegramConfig, expiredDomains, true);
        }
      } catch (error) {
        console.error('发送Telegram通知失败: ' + error.message);
      }
    }
  }
}

// 发送域名通知（即将到期或已过期）
async function sendExpiringDomainsNotification(config, domains, isExpired) {
  if (domains.length === 0) return;
  
  // 构建消息内容
  let title = isExpired ? 
    '🚫 <b>域名已过期提醒</b> 🚫' : 
    '🚨 <b>域名到期提醒</b> 🚨';
  
  // 根据不同通知类型使用不同长度的等号分隔线
  // 域名到期提醒使用19个字符，域名已过期提醒使用21个字符
  const separator = isExpired ? 
    '=====================' : 
    '===================';
  // 域名之间的短横线分隔符统一使用40个字符
  const domainSeparator = '----------------------------------------';
  
  message = title + '\n' + separator + '\n\n';
  
  domains.forEach((domain, index) => {
    const expiryDate = new Date(domain.expiryDate);
    const today = new Date();
    const daysLeft = Math.ceil((expiryDate - today) / (1000 * 60 * 60 * 24));
    
    if (index > 0) {
      message += '\n' + domainSeparator + '\n\n';
    }
    
    message += '🌍 <b>域名:</b> ' + domain.name + '\n\n';
    if (domain.registrar) {
      message += '🏬 <b>注册商:</b> ' + domain.registrar + '\n\n';
    }
    message += '⏳ <b>剩余时间:</b> ' + daysLeft + ' 天\n\n';
    message += '📅 <b>到期日期:</b> ' + formatDate(domain.expiryDate) + '\n\n';
    
    if (domain.renewLink) {
      message += '⚠️ <b>点击续期:</b> ' + domain.renewLink + '\n\n';
    } else {
      message += '⚠️ <b>点击续期:</b> 未设置续期链接\n\n';
    }
  });
  
  // 发送消息
  return await sendTelegramMessage(config, message);
}

// 添加测试单个域名通知的后端函数
async function testSingleDomainNotification(id) {
  // 获取域名信息
  const domains = await getDomains();
  const domain = domains.find(d => d.id === id);
  
  if (!domain) {
    throw new Error('域名不存在');
  }
  
  // 获取Telegram配置
  const telegramConfig = await getTelegramConfigWithToken();
  
  if (!telegramConfig.enabled) {
    throw new Error('Telegram通知未启用');
  }
  
  if (!telegramConfig.botToken && typeof TG_TOKEN === 'undefined') {
    throw new Error('未配置Telegram机器人Token');
  }
  
  if (!telegramConfig.chatId && typeof TG_ID === 'undefined') {
    throw new Error('未配置Telegram聊天ID');
  }
  
  // 构建测试消息
  const expiryDate = new Date(domain.expiryDate);
  const today = new Date();
  const daysLeft = Math.ceil((expiryDate - today) / (1000 * 60 * 60 * 24));
  const isExpired = daysLeft <= 0;
  
  let title = isExpired ? 
    '🚫 <b>域名已过期测试通知</b> 🚫' : 
    '🚨 <b>域名到期测试通知</b> 🚨';
  
  // 根据不同通知类型使用不同长度的分隔线
  // 域名到期测试通知使用23个字符，域名已过期测试通知使用25个字符
  const separator = isExpired ? 
    '=========================' : 
    '=======================';
  
  
  let message = title + '\n' + separator + '\n\n';
  message += '这是一条测试通知，用于预览域名' + (isExpired ? '已过期' : '到期') + '提醒的格式：\n\n';
  
  message += '🌍 <b>域名:</b> ' + domain.name + '\n\n';
  if (domain.registrar) {
    message += '🏬 <b>注册商:</b> ' + domain.registrar + '\n\n';
  }
  message += '⏳ <b>剩余时间:</b> ' + daysLeft + ' 天\n\n';
  message += '📅 <b>到期日期:</b> ' + formatDate(domain.expiryDate) + '\n\n';
  
  if (domain.renewLink) {
    message += '⚠️ <b>点击续期:</b> ' + domain.renewLink + '\n\n';
  } else {
    message += '⚠️ <b>点击续期:</b> 未设置续期链接\n\n';
  }
  
  // 发送测试消息
  const result = await sendTelegramMessage(telegramConfig, message);
  return { success: true, message: '测试通知已发送' };
}

// 格式化日期
function formatDate(dateString) {
  const date = new Date(dateString);
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return year + '-' + month + '-' + day;
}

// 将天数转换为年月日格式
function formatDaysToYMD(days) {
  if (days <= 0) return '';
  
  const years = Math.floor(days / 365);
  const remainingDaysAfterYears = days % 365;
  const months = Math.floor(remainingDaysAfterYears / 30);
  const remainingDays = remainingDaysAfterYears % 30;
  
  let result = '';
  
  if (years > 0) {
    result += years + '年';
  }
  
  if (months > 0) {
    result += months + '个月';
  }
  
  if (remainingDays > 0) {
    result += remainingDays + '天';
  }
  
  return result;
}

// 注册Cloudflare Workers事件处理程序
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

// 注册定时任务，每天检查一次
addEventListener('scheduled', event => {
  event.waitUntil(checkExpiringDomains());
});

// 添加页面底部版权信息
function addCopyrightFooter(html) {
  // 定义页脚内容和样式，只需要修改这里
  // 页脚文字大小
  const footerFontSize = '14px';
  // 页脚图标大小
  const footerIconSize = '14px';
  // 页脚图标颜色（使用CSS颜色值，如：#4e54c8、blue、rgba(0,0,0,0.7)等）
  const footerIconColor = 'white';
  
  const footerContent = `<span style="color: white;">Copyright © 2025 Faiz</span> | <i class="iconfont icon-github" style="font-size: ${footerIconSize}; color: ${footerIconColor};"></i><a href="https://github.com/kamanfaiz" target="_blank" style="color: white; text-decoration: none;">GitHub Repository</a> | <i class="iconfont icon-book" style="font-size: ${footerIconSize}; color: ${footerIconColor};"></i><a href="https://blog.faiz.hidns.co/" target="_blank" style="color: white; text-decoration: none;">Faiz博客</a>`;
  
  const bodyEndIndex = html.lastIndexOf('</body>');
  
  // 如果找到了</body>标签
  if (bodyEndIndex !== -1) {
    // 在</body>标签前插入页脚和相关脚本
    const footer = `
      <style>
        html {
          height: 100%;
        }
        body {
          min-height: 100%;
          display: flex;
          flex-direction: column;
        }
        .content-wrapper {
          flex: 1 0 auto;
        }
        #copyright-footer {
          flex-shrink: 0;
          text-align: center;
          padding: 10px;
          font-size: ${footerFontSize};
          border-top: 1px solid rgba(255, 255, 255, 0.18);
          margin-top: auto;
          background-color: rgba(0, 0, 0, 0.2);
          backdrop-filter: blur(5px);
          -webkit-backdrop-filter: blur(5px);
          color: white;
          text-shadow: 0 1px 2px rgba(0, 0, 0, 0.3);
        }
      </style>
      
      <footer id="copyright-footer">
        ${footerContent}
      </footer>
      
      <script>
        // 页面加载完成后执行
        document.addEventListener('DOMContentLoaded', function() {
          // 将body内的所有内容（除了页脚）包裹在一个div中
          const footer = document.getElementById('copyright-footer');
          const contentWrapper = document.createElement('div');
          contentWrapper.className = 'content-wrapper';
          
          // 将body中除页脚外的所有元素移到contentWrapper中
          while (document.body.firstChild !== footer) {
            if (document.body.firstChild) {
              contentWrapper.appendChild(document.body.firstChild);
            } else {
              break;
            }
          }
          
          // 将contentWrapper插入到body的开头
          document.body.insertBefore(contentWrapper, footer);
        });
      </script>
    `;
    
    return html.slice(0, bodyEndIndex) + footer + html.slice(bodyEndIndex);
  }
  
  // 如果没找到</body>标签，就直接添加到HTML末尾
  const footerHtml = `
    <div style="text-align: center; padding: 10px; font-size: ${footerFontSize}; margin-top: 20px; border-top: 1px solid rgba(255, 255, 255, 0.18); background-color: rgba(0, 0, 0, 0.2); backdrop-filter: blur(5px); -webkit-backdrop-filter: blur(5px); color: white; text-shadow: 0 1px 2px rgba(0, 0, 0, 0.3);">
      ${footerContent}
    </div>
  `;
  
  // 在</body>标签前插入页脚
  return html.replace('</body>', `${footerHtml}</body>`);
}

// 修改响应处理，添加版权信息
async function addFooterToResponse(response) {
  const contentType = response.headers.get('Content-Type') || '';
  
  // 只处理HTML响应
  if (contentType.includes('text/html')) {
    const html = await response.text();
    const modifiedHtml = addCopyrightFooter(html);
    
    return new Response(modifiedHtml, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers
    });
  }
  
  return response;
}
