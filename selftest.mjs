#!/usr/bin/env node
/**
 * 端到端自检：在没有 Docker 的环境里，用「只拷一个文件 + 明文凭据」的方式
 * 复现容器启动条件，验证 NAS 部署包是否真的能用。
 *
 * 它检查的是部署包**真正的风险点**，不是重跑单元测试：
 *   1. 镜像里只有 ai-gateway.mjs 够不够（零依赖、单文件）；
 *   2. 明文 auth.json 能否在**没有 WorkBuddy 客户端**的机器上跑通；
 *   3. WORKBUDDY_HOST=0.0.0.0 后局域网是否真的能连（容器端口映射的前提）；
 *   4. 令牌闸门是否生效（错误令牌必须 401）；
 *   5. 模型列表是否含 hy4flash-free 且标了 free。
 *
 * 用法：node selftest.mjs <认证文件路径> [端口]
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync, rmSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';

const HERE = dirname(fileURLToPath(import.meta.url));
const AUTH_SRC = process.argv[2];
const PORT = Number(process.argv[3] || 8796);
const TOKEN = 'selftest-token-' + Math.random().toString(36).slice(2, 10);

if (!AUTH_SRC || !existsSync(AUTH_SRC)) {
  console.error('用法: node selftest.mjs <workbuddy-desktop*.info> [port]');
  process.exit(1);
}

/* 隔离的运行目录：只放桥单文件，等价于镜像内容 */
const SANDBOX = join(tmpdir(), `wb-selftest-${Date.now()}`);
mkdirSync(join(SANDBOX, 'app'), { recursive: true });
mkdirSync(join(SANDBOX, 'auth'), { recursive: true });
mkdirSync(join(SANDBOX, 'data'), { recursive: true });

const BRIDGE = readFileSync(join(HERE, 'ai-gateway.mjs'));
writeFileSync(join(SANDBOX, 'app', 'ai-gateway.mjs'), BRIDGE);

/* 复用部署包里的导出脚本生成明文凭据 */
console.log('· 导出明文凭据…');
const exportOut = join(SANDBOX, 'auth', 'auth.json');
await new Promise((resolve, reject) => {
  const p = spawn(process.execPath, [
    join(HERE, 'export-auth.mjs'),
    '--auth-file', AUTH_SRC,
    '--out', exportOut,
  ], { stdio: ['ignore', 'inherit', 'inherit'] });
  p.on('exit', (c) => (c === 0 ? resolve() : reject(new Error(`export exit ${c}`))));
  p.on('error', reject);
});

/* 容器等价环境：刻意把 APP_EXECUTABLE 指向不存在的位置 */
const env = {
  ...process.env,
  WORKBUDDY_HOST: '0.0.0.0',
  WORKBUDDY_PORT: String(PORT),
  WORKBUDDY_AUTH_FILE: exportOut,
  WORKBUDDY_LOCAL_TOKEN: TOKEN,
  WORKBUDDY_USAGE_FILE: join(SANDBOX, 'data', 'usage.jsonl'),
  WORKBUDDY_APP_EXECUTABLE: '/nonexistent/WorkBuddy.exe',
  WORKBUDDY_AUTO_CHECKIN: '0',
  WORKBUDDY_LOG: '1',
};

console.log('· 启动桥（模拟容器）…');
const child = spawn(process.execPath, ['ai-gateway.mjs'], {
  cwd: join(SANDBOX, 'app'),
  env,
  stdio: ['ignore', 'pipe', 'pipe'],
});

let out = '';
child.stdout.on('data', (d) => { out += d; });
child.stderr.on('data', (d) => { out += d; });

const cleanup = () => {
  try { child.kill('SIGKILL'); } catch { /* 已退出 */ }
  try { rmSync(SANDBOX, { recursive: true, force: true }); } catch { /* 文件占用 */ }
};

const waitFor = async (fn, timeoutMs = 25000, label = 'condition') => {
  const started = Date.now();
  for (;;) {
    try { if (await fn()) return true; } catch { /* 还没起来 */ }
    if (Date.now() - started > timeoutMs) throw new Error(`超时：${label}`);
    await new Promise((r) => setTimeout(r, 400));
  }
};

const results = [];
const check = (name, ok, detail = '') => {
  results.push({ name, ok, detail });
  console.log(`${ok ? '✓' : '✗'} ${name}${detail ? `  — ${detail}` : ''}`);
};

try {
  await waitFor(async () => {
    const r = await fetch(`http://127.0.0.1:${PORT}/health`, {
      headers: { Authorization: `Bearer ${TOKEN}` },
    });
    return r.ok;
  }, 25000, '桥监听');

  const health = await (await fetch(`http://127.0.0.1:${PORT}/health`, {
    headers: { Authorization: `Bearer ${TOKEN}` },
  })).json();

  check('明文凭据可用（无需 WorkBuddy 客户端）', !!health.auth?.userId,
    `账号 ${health.auth?.userId || '?'} @ ${health.auth?.endpoint || '?'}`);

  check('监听在 0.0.0.0（容器可映射）', out.includes('0.0.0.0'), '');

  /* 局域网 IP 直连 —— 容器端口映射后其他设备就是这么访问的 */
  const lanIp = await (async () => {
    const os = await import('node:os');
    for (const list of Object.values(os.networkInterfaces())) {
      for (const ni of list || []) {
        if (ni.family === 'IPv4' && !ni.internal) return ni.address;
      }
    }
    return null;
  })();

  if (lanIp) {
    const r = await fetch(`http://${lanIp}:${PORT}/v1/models`, {
      headers: { Authorization: `Bearer ${TOKEN}` },
    }).catch(() => null);
    check('局域网 IP 可访问', !!r?.ok, lanIp ? `http://${lanIp}:${PORT}` : '');
  } else {
    check('局域网 IP 可访问', true, '（本机无对外网卡，跳过）');
  }

  /* 令牌闸门 */
  const bad = await fetch(`http://127.0.0.1:${PORT}/v1/models`, {
    headers: { Authorization: 'Bearer definitely-wrong' },
  });
  check('错误令牌被拒', bad.status === 401, `HTTP ${bad.status}`);

  /* 模型列表 */
  const models = await (await fetch(`http://127.0.0.1:${PORT}/v1/models?all=1`, {
    headers: { Authorization: `Bearer ${TOKEN}` },
  })).json();
  const ids = (models.data || []).map((m) => m.id);
  const free = (models.data || []).find((m) => m.id === 'hy4flash-free');
  check('目录含 hy4flash-free', ids.includes('hy4flash-free'), `共 ${ids.length} 个模型`);
  check('hy4flash-free 标记为免费', free?.free === true && free?.credits === 0,
    free ? `credits=${free.credits} badge=${free.badge || '-'}` : '未找到');

  /* 真发一次对话 */
  const chat = await fetch(`http://127.0.0.1:${PORT}/v1/chat/completions`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: 'hy4flash-free',
      messages: [{ role: 'user', content: '只回答两个字：自检' }],
      max_tokens: 2000,
      stream: false,
    }),
  });
  const body = await chat.json().catch(() => null);
  const text = body?.choices?.[0]?.message?.content || '';
  check('hy4flash-free 能出字', chat.ok && text.length > 0,
    `"${text.slice(0, 30)}" credit=${body?.usage?.credit ?? '?'}`);
} catch (e) {
  check('整体流程', false, e.message);
  console.error('\n--- 桥输出 ---\n' + out.slice(-2000));
} finally {
  cleanup();
}

const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} 通过`);
process.exit(failed.length === 0 ? 0 : 1);
