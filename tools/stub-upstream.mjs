/**
 * 假上游：验证桥在 429 时是否把 Retry-After 传给调用方。
 * 只用于本地验证，不进部署包。
 */
import { createServer } from 'node:http';

const MODE = process.env.STUB_MODE || '429';
const PORT = Number(process.env.STUB_PORT || 8899);

createServer((req, res) => {
  let body = '';
  req.on('data', (d) => { body += d; });
  req.on('end', () => {
    if (MODE === '429' && req.url.includes('/chat/completions')) {
      // 上游常见的两种形态：带 retry-after 头 / 只在 body 里给 / 都不给
      const headers = { 'Content-Type': 'application/json' };
      if (process.env.STUB_NO_RETRY_AFTER !== '1') headers['retry-after'] = '7';
      res.writeHead(429, headers);
      res.end(JSON.stringify({ code: 14003, msg: 'too many requests' }));
      return;
    }
    // 正常响应（SSE）
    res.writeHead(200, { 'Content-Type': 'text/event-stream' });
    res.write(`data: ${JSON.stringify({ choices: [{ delta: { content: 'ok' } }] })}\n\n`);
    res.write('data: [DONE]\n\n');
    res.end();
  });
}).listen(PORT, '127.0.0.1', () => console.log('stub up on', PORT, 'mode', MODE));
