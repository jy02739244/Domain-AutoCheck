// 测试环境下 mock cloudflare:sockets，让 vitest 能加载 src/index.js
// 注意：测试只 import 纯函数（escape / auth / sanitize），不会真正调用 connect()，
// 这里的 mock 只为了让顶层 import 不报错。
export function connect() {
  throw new Error('cloudflare:sockets.connect() called in test — should not happen');
}
