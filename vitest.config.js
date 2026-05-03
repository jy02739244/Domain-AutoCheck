import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

export default defineConfig({
  resolve: {
    alias: {
      // 让测试 import src/index.js 时，cloudflare:sockets 别名到本地 mock
      'cloudflare:sockets': fileURLToPath(
        new URL('./test/cloudflare-sockets-mock.js', import.meta.url)
      ),
    },
  },
});
