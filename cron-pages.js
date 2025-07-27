/**
 * 外部 Cron Worker 示例
 * 用于触发域名监控系统的定时检查
 * 
 * 使用方法：
 * 1. 创建一个新的 Cloudflare Worker
 * 2. 将此代码复制到 Worker 中
 * 3. 设置环境变量：
 *    - PAGES_DOMAIN: 你的 Pages 域名（例如：your-app.pages.dev）
 *    - CRON_SECRET: 安全密钥（可选，与主应用中的 CRON_SECRET 保持一致）
 * 4. 在 Worker 设置中添加 Cron 触发器：
 *    - 例如：0 5 * * * （每天早上5点）
 */

export default {
  async scheduled(event, env, ctx) {
    try {
      // 获取配置
      const pagesDomain = env.PAGES_DOMAIN;
      const cronSecret = env.CRON_SECRET;
      
      if (!pagesDomain) {
        console.error('PAGES_DOMAIN environment variable is not set');
        return;
      }
      
      // 构建请求 URL
      const url = `https://${pagesDomain}/api/cron-check`;
      
      // 构建请求头
      const headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'Cloudflare-Cron-Worker/1.0'
      };
      
      // 如果设置了密钥，添加认证头
      if (cronSecret) {
        headers['Authorization'] = `Bearer ${cronSecret}`;
      }
      
      console.log(`Triggering cron job at: ${url}`);
      
      // 发送请求
      const response = await fetch(url, {
        method: 'POST',
        headers: headers,
        // 设置超时时间
        signal: AbortSignal.timeout(30000) // 30秒超时
      });
      
      if (!response.ok) {
        const errorText = await response.text();
        console.error(`Cron job failed with status ${response.status}: ${errorText}`);
        throw new Error(`HTTP ${response.status}: ${errorText}`);
      }
      
      const result = await response.json();
      console.log('Cron job completed successfully:', result);
      
    } catch (error) {
      console.error('Cron worker error:', error);
      
      // 可选：发送错误通知到其他服务
      // 例如发送到 Slack、Discord 或其他监控服务
      
      // 重新抛出错误以便 Cloudflare 记录
      throw error;
    }
  },
  
  // 可选：添加 fetch 处理器用于手动触发或健康检查
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    
    // 健康检查端点
    if (url.pathname === '/health') {
      return new Response(JSON.stringify({
        status: 'ok',
        timestamp: new Date().toISOString(),
        worker: 'cron-worker'
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // 手动触发端点（用于测试）
    if (url.pathname === '/trigger' && request.method === 'POST') {
      try {
        // 模拟 scheduled 事件
        await this.scheduled(null, env, ctx);
        return new Response(JSON.stringify({
          success: true,
          message: 'Cron job triggered manually'
        }), {
          headers: { 'Content-Type': 'application/json' }
        });
      } catch (error) {
        return new Response(JSON.stringify({
          success: false,
          error: error.message
        }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }
    
    return new Response('Cron Worker - Use /health for status or POST /trigger for manual execution', {
      status: 404
    });
  }
};
