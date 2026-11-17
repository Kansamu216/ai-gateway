#!/usr/bin/env node
/**
 * workbuddy-console —— 桥的网页管理面（一个文件、零依赖）。
 *
 * 为什么单独一个进程，而不是塞进桥里：
 *   桥是「给客户端用的 OpenAI 接口」，控制台是「给人用的管理面」。两者的
 *   鉴权模型、失败模式、暴露面完全不同 —— 桥挂了不该连管理页都打不开；
 *   管理页更不该因为桥的一个 bug 被拖下水。所以分成两个进程、两个端口。
 *
 * 它做的事（刻意保持少而全）：
 *   1. 看：账号、额度、令牌到期倒计时、模型列表、用量、最近失败；
 *   2. 登录：走 WorkBuddy 官方的**网页登录**流程（见下），一键拿新令牌；
 *   3. 换：上传/粘贴凭据，校验后热加载桥，不需要 SSH 传文件；
 *   4. 管：给每台设备发/删 API key，改完自动重启桥。
 *
 * ## 登录是怎么做到的（重要，安全边界在这里）
 *
 * WorkBuddy 桌面端用的是「网页回跳」流程，我们照着实现，**账号密码永远不经过
 * 这台 NAS**：
 *
 *   ① 容器向官方网关 `POST /v2/plugin/auth/state?platform=workbuddy`
 *      → 得到 { state, authUrl }
 *   ② 把这个 authUrl 给用户的浏览器打开（它就是官方登录页）
 *   ③ 用户在**自己的浏览器**里输入账号密码 / 扫码 —— 请求直达官方服务器
 *   ④ 容器轮询 `GET /v2/plugin/auth/token?state=...`
 *      → 未登录时返回 code 11217（"login ing..."），登录成功后返回令牌
 *
 * 所以 NAS 只看到“一个 state 字符串”和“最终令牌”，看不到密码，也不代理
 * 用户的任何登录请求。这是与「在网页里代填账号密码」的本质区别。
 *
 * 它不做的事（避免变成第二个大系统）：
 *   · 不做对话界面 —— 那是客户端的事；
 *   · 不做用户体系 —— 一个口令，够个人 NAS 用；
 *   · 不写数据库 —— 三份 JSON 文件，出问题肉眼可查。
 */

import { createServer, request as requestImpl } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { readFileSync, writeFileSync, existsSync, mkdirSync, renameSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, createDecipheriv, randomBytes, timingSafeEqual, createHmac } from 'node:crypto';
import { spawn } from 'node:child_process';

const HERE = dirname(fileURLToPath(import.meta.url));
const DATA = envRaw('DATA_DIR') || '/data';
const AUTH_PATH = join(DATA, 'auth.json');
const CONFIG_PATH = join(DATA, 'config.json');
const USAGE_PATH = join(DATA, 'usage.jsonl');

const PORT = Number(envRaw('CONSOLE_PORT') || 8792);
const HOST = envRaw('CONSOLE_HOST') || '0.0.0.0';
const BRIDGE_PORT = Number(envRaw('PORT') || 8790);

const BRIDGE_SCRIPT = join(HERE, 'ai-gateway.mjs');

mkdirSync(DATA, { recursive: true });

/**
 * 读一个配置项：优先 `AIGW_*`，回退旧名 `WORKBUDDY_*`。
 * 与 ai-gateway.mjs 里同名函数保持一致 —— 两个进程共用一套命名约定，
 * 否则会出现「控制台改了新名、代理还在读旧名」的静默错配。
 */
function envRaw(name) {
  const v = process.env[`AIGW_${name}`];
  if (v !== undefined && v !== '') return v;
  return process.env[`WORKBUDDY_${name}`];
}

/* ── 配置与状态 ──────────────────────────────────────────────────────── */

const defaults = {
  // 管理页口令。首次启动自动生成并打印到日志（与桥的令牌策略一致）。
  consolePassword: '',
  // 给客户端用的 key 列表：[{ id, key, label, createdAt }]
  clientKeys: [],
  // 桥的本地令牌（控制台内部调用桥 API 用，不对外）
  bridgeToken: '',
  // 解密上传的 .info 需要它。由「导出脚本」或设置页填入。
  atrestKey: '',
  /*
   * 并发上限（同时打到上游的请求数）。默认 1 —— 上游对单账号是串行的，
   * 让它排队比全推上去更快也更稳。0 = 不限（会退回"全推"的旧行为）。
   */
  maxConcurrency: 1,
};

function loadJson(file, fallback) {
  try {
    if (!existsSync(file)) return structuredClone(fallback);
    return { ...structuredClone(fallback), ...JSON.parse(readFileSync(file, 'utf8')) };
  } catch {
    return structuredClone(fallback);
  }
}

/** 原子写：先写临时文件再 rename，避免断电/并发留下半个 JSON。 */
function saveJson(file, value) {
  const tmp = `${file}.tmp`;
  writeFileSync(tmp, JSON.stringify(value, null, 2), { encoding: 'utf8', mode: 0o600 });
  renameSync(tmp, file);
}

let config = loadJson(CONFIG_PATH, defaults);

if (!config.consolePassword) {
  config.consolePassword = randomBytes(12).toString('base64url');
  saveJson(CONFIG_PATH, config);
  console.log(`[console] 首次启动，管理口令已生成：${config.consolePassword}`);
  console.log('[console] 登录后可在「设置」里改成自己的口令');
}
if (!config.bridgeToken) {
  config.bridgeToken = randomBytes(24).toString('base64url');
  saveJson(CONFIG_PATH, config);
  // 桥进程要用同一把，靠环境变量传下去（写在这里就够，重启会复用）
  console.log('[console] 已生成桥令牌（内部使用）');
}

/** 会话签名密钥：由口令派生，改口令即让所有旧会话失效。 */
const sessionSecret = () =>
  createHash('sha256').update(`wb-session:${config.consolePassword}`).digest();

/* ── 桥进程管理 ──────────────────────────────────────────────────────── */

let bridge = null;
let bridgeLog = [];      // 最近若干行，管理页排障用
let bridgeStartedAt = 0;

function pushBridgeLog(line) {
  const text = String(line).trimEnd();
  if (!text) return;
  bridgeLog.push(text);
  if (bridgeLog.length > 200) bridgeLog = bridgeLog.slice(-200);
}

function bridgeEnv() {
  const env = {
    ...process.env,
    /*
     * 桥必须听 0.0.0.0，不能听 127.0.0.1。
     *
     * 容器里的回环是**容器自己的**回环，宿主机的端口映射（8790:8790）
     * 打不进去 —— 实测表现为「端口在监听但外部连接被拒」。容器网络本身已经
     * 是隔离的（只有 compose 里 publish 的端口才出去），所以听 0.0.0.0 不会
     * 多暴露任何东西。
     *
     * 想强制只听回环（例如只让控制台代理、不直接暴露 8790）时，把它设成
     * 127.0.0.1 —— 但那时 client 只能走控制台，控制台目前不做 /v1 转发。
     */
    WORKBUDDY_HOST: envRaw('BIND') || '0.0.0.0',
    WORKBUDDY_PORT: String(BRIDGE_PORT),
    WORKBUDDY_AUTH_FILE: AUTH_PATH,
    WORKBUDDY_LOCAL_TOKEN: config.bridgeToken,
    WORKBUDDY_USAGE_FILE: USAGE_PATH,
    // 容器里没有 WorkBuddy 客户端；指到不存在的位置让日志不再猜路径
    WORKBUDDY_APP_EXECUTABLE: '/nonexistent/WorkBuddy.exe',
    WORKBUDDY_LOG: '1',
    WORKBUDDY_LEDGER_IDLE_FLUSH_MS: '2000',
    /*
     * 并发上限：上游对单账号是**串行**的（实测同时 3 个请求耗时严格递增），
     * 桥这边若把请求全推上去，只会让上游队列越堆越长、还容易撞 429。
     * 压到 1 = 完全按上游的实际处理能力排队，排队发生在本地、无上游副作用。
     * 想放开可设 2~3（上游偶尔能并行），0 = 关闭闸门。
     */
    WORKBUDDY_MAX_CONCURRENCY: String(config.maxConcurrency ?? 1),
  };

  /*
   * ⚠️ 端口与数据目录必须由控制台**单向决定**，不能被外层继承值带偏。
   *
   * 为什么会有这个坑：这份 env 是从 `process.env` 展开的，而容器里
   * Dockerfile 设了 `AIGW_PORT=8790` / `AIGW_DATA_DIR=/data`。子进程于是
   * 同时看到「继承的 AIGW_*」和「我们要传的 WORKBUDDY_*」，而 envRaw
   * 优先读 AIGW_* —— 外层那个旧值会赢，改端口/改目录静默失效。
   *
   * 正确语义：控制台是唯一决策者。它算出的 BRIDGE_PORT / DATA 写进**两种
   * 前缀**，子进程无论按哪个名字读都得到同一个值，不存在歧义。
   */
  env.WORKBUDDY_PORT = String(BRIDGE_PORT);
  env.AIGW_PORT = String(BRIDGE_PORT);
  env.WORKBUDDY_DATA_DIR = DATA;
  env.AIGW_DATA_DIR = DATA;

  const keys = config.clientKeys.map((k) => k.key).filter(Boolean);
  if (keys.length) {
    env.WORKBUDDY_CLIENT_KEYS = keys.join(',');
    env.AIGW_CLIENT_KEYS = keys.join(',');
  } else {
    delete env.WORKBUDDY_CLIENT_KEYS;
    delete env.AIGW_CLIENT_KEYS;
  }
  return env;
}

function startBridge() {
  if (bridge) return;
  if (!existsSync(BRIDGE_SCRIPT)) {
    pushBridgeLog(`[console] 找不到桥脚本：${BRIDGE_SCRIPT}`);
    return;
  }
  bridge = spawn(process.execPath, [BRIDGE_SCRIPT], {
    cwd: HERE,
    env: bridgeEnv(),
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  bridgeStartedAt = Date.now();
  bridge.stdout.on('data', (d) => String(d).split('\n').forEach(pushBridgeLog));
  bridge.stderr.on('data', (d) => String(d).split('\n').forEach(pushBridgeLog));
  bridge.on('exit', (code, signal) => {
    pushBridgeLog(`[console] 桥退出 code=${code} signal=${signal}`);
    bridge = null;
    // 异常退出就退避重启；正常 stop 由 restartBridge 控制，不会走到这
    if (!stopping) setTimeout(() => { if (!bridge) startBridge(); }, 1500);
  });
  pushBridgeLog('[console] 已启动代理');
}

let stopping = false;

async function stopBridge() {
  const child = bridge;
  if (!child) return;
  stopping = true;
  await new Promise((resolve) => {
    const done = () => resolve();
    child.once('exit', done);
    try { child.kill('SIGTERM'); } catch { done(); }
    // 3 秒还没退就强杀：桥没有需要优雅收尾的持久状态
    setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* 已退 */ } done(); }, 3000);
  });
  bridge = null;
  stopping = false;
}

async function restartBridge() {
  // 等端口真正释放再起，否则新进程会 EADDRINUSE 撞死
  await stopBridge();
  await new Promise((r) => setTimeout(r, 700));
  startBridge();
  await new Promise((r) => setTimeout(r, 500));
}

/* ── 凭据处理 ────────────────────────────────────────────────────────── */

const ATREST_AAD_DOMAIN = Buffer.from('WB-AAD\0', 'ascii');

const encodeLengthPrefixed = (v) => {
  const b = Buffer.from(v, 'utf8');
  const len = Buffer.allocUnsafe(4);
  len.writeUInt32BE(b.length);
  return Buffer.concat([len, b]);
};

const atRestFieldAad = (keyId, suite) => {
  const s = Buffer.allocUnsafe(4);
  s.writeUInt32BE(suite);
  return Buffer.concat([
    ATREST_AAD_DOMAIN, Buffer.from([1]),
    encodeLengthPrefixed('WBEV1'), encodeLengthPrefixed('sym-v1'),
    s, encodeLengthPrefixed(keyId),
    Buffer.from([2]), Buffer.from([0]), Buffer.from([0]),
  ]);
};

const atRestKeyId = (key) => createHash('sha256').update(key).digest('hex').slice(0, 16);

const isEncryptedField = (v) => {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return false;
  const keys = Object.keys(v).sort();
  return keys.length === 2 && keys[0] === '$wbEncrypted' && keys[1] === 'envelope'
    && v.$wbEncrypted === 1 && typeof v.envelope === 'string';
};

/** 把登录文件里的字段取出明文：已是字符串就原样返回，是信封则解密。 */
function openField(value, label, key) {
  if (typeof value === 'string') return value;
  if (!isEncryptedField(value)) return '';
  const envelope = JSON.parse(Buffer.from(value.envelope, 'base64').toString('utf8'));
  if (!key) {
    throw new Error(`${label} 是加密的，需要先提供 AtRest 密钥（设置页里填，或用导出脚本）`);
  }
  const expected = atRestKeyId(key);
  if (envelope.keyId !== expected) {
    throw new Error(`${label} 的 keyId 与提供的密钥不匹配（可能是另一台机器的客户端写出的）`);
  }
  const d = createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.nonce, 'base64'), { authTagLength: 16 });
  d.setAAD(atRestFieldAad(envelope.keyId, envelope.suite));
  d.setAuthTag(Buffer.from(envelope.authTag, 'base64'));
  return Buffer.concat([d.update(Buffer.from(envelope.ciphertext, 'base64')), d.final()]).toString('utf8');
}

/**
 * 把用户提供的原始内容转成桥能用的明文 auth.json。
 * 接受两种输入：桌面端的 .info（可能加密）或已导出的 auth.json（明文）。
 * @returns {{ ok: true, auth: object, account: string, endpoint: string, expiresAt: number } | { ok: false, error: string }}
 */
function normalizeCredential(rawText) {
  let raw;
  try {
    raw = JSON.parse(rawText);
  } catch {
    return { ok: false, error: '不是合法的 JSON —— 请确认上传的是 .info 或 auth.json 文件' };
  }
  const auth = raw.auth || raw;

  if (typeof auth !== 'object' || auth === null) {
    return { ok: false, error: '文件结构不对：缺少 auth 字段' };
  }
  const hasToken = !!auth.accessToken;
  if (!hasToken) {
    return { ok: false, error: '文件里没有 accessToken —— 这份登录文件可能已损坏或未登录' };
  }

  const key = config.atrestKey ? Buffer.from(config.atrestKey, 'base64') : null;
  let access;
  let refresh;
  try {
    access = openField(auth.accessToken, 'accessToken', key);
    refresh = openField(auth.refreshToken, 'refreshToken', key);
  } catch (e) {
    return { ok: false, error: e.message };
  }
  if (!access) return { ok: false, error: '解不出 accessToken' };

  const claims = (() => {
    try { return JSON.parse(Buffer.from(access.split('.')[1], 'base64url').toString('utf8')); } catch { return {}; }
  })();
  const domain = auth.domain || claims.iss || '';
  const endpoint = (() => {
    const d = String(domain);
    if (d.includes('workbuddy.ai') || d.includes('workbuddy.cc')) return 'https://www.workbuddy.ai';
    if (d.includes('codebuddy.ai')) return 'https://www.codebuddy.ai';
    return 'https://copilot.tencent.com';
  })();

  return {
    ok: true,
    auth: {
      accessToken: access,
      refreshToken: refresh,
      domain,
      expiresAt: Number(auth.expiresAt || claims.exp * 1000 || 0),
      refreshExpiresAt: Number(auth.refreshExpiresAt || 0),
    },
    account: claims.sub || '',
    endpoint,
    expiresAt: Number(auth.expiresAt || claims.exp * 1000 || 0),
  };
}

function readAuthSummary() {
  try {
    if (!existsSync(AUTH_PATH)) return null;
    const raw = JSON.parse(readFileSync(AUTH_PATH, 'utf8'));
    const a = raw.auth || {};
    const claims = (() => {
      try { return JSON.parse(Buffer.from(String(a.accessToken).split('.')[1], 'base64url').toString('utf8')); } catch { return {}; }
    })();
    return {
      account: claims.sub || '',
      domain: a.domain || '',
      expiresAt: Number(a.expiresAt || 0),
      hasRefresh: !!a.refreshToken,
    };
  } catch {
    return null;
  }
}

/* ── 调桥的内部 API ──────────────────────────────────────────────────── */

/** GET 桥的某个接口；超时或连不上返回 null（管理页据此显示「桥未运行」）。 */
async function bridgeGet(path, timeoutMs = 12000) {
  return new Promise((resolve) => {
    const req = requestImpl({
      host: '127.0.0.1',
      port: BRIDGE_PORT,
      path,
      method: 'GET',
      headers: { Authorization: `Bearer ${config.bridgeToken}` },
    });
    const timer = setTimeout(() => {
      try { req.destroy(); } catch { /* 已结束 */ }
      resolve(null);
    }, timeoutMs);
    req.on('response', (res) => {
      let body = '';
      res.on('data', (d) => { body += d; });
      res.on('end', () => {
        clearTimeout(timer);
        try { resolve({ status: res.statusCode, json: JSON.parse(body) }); }
        catch { resolve({ status: res.statusCode, json: null }); }
      });
    });
    req.on('error', () => { clearTimeout(timer); resolve(null); });
    req.end();
  });
}

/* ── WorkBuddy 官方网页登录（设备授权式轮询）────────────────────────────
 *
 * 流程与桌面端完全一致，只是把「打开浏览器」这一动作交给用户：
 *   state  →  官方登录页  →  轮询换令牌  →  写入 auth.json  →  重启桥
 *
 * 关键的三个接口（均已实测）：
 *   POST /v2/plugin/auth/state?platform=workbuddy   → { state, authUrl }
 *   GET  /v2/plugin/auth/token?state=<state>        → 11217 等待 / 200 令牌
 *
 * 为什么必须带那一串 X-No-* 头：这些头告诉网关「这是未登录的登录请求，
 * 不要按已登录用户去校验」，否则会在鉴权中间件就被拒。
 */

/** 从登录文件里推断该用哪个网关（国际版 / 国内版域名不同）。 */
function loginGateway() {
  const auth = readAuthSummary();
  const d = String(auth?.domain || '');
  if (d.includes('workbuddy.ai') || d.includes('workbuddy.cc') || d.includes('codebuddy.ai')) {
    return { origin: 'https://www.workbuddy.ai', label: '国际版' };
  }
  // 没有凭据时默认国内版 —— 本部署就是国内版
  return { origin: 'https://copilot.tencent.com', label: '国内版' };
}

const LOGIN_HEADERS = {
  'Content-Type': 'application/json',
  'X-No-Authorization': 'true',
  'X-No-User-Id': 'true',
  'X-No-Enterprise-Id': 'true',
  'X-No-Department-Info': 'true',
  'User-Agent': 'WorkBuddy/4.9.29177644',
};

/** 发一个 JSON 请求到官方网关（走 https，超时可控）。 */
function gatewayJson(origin, path, { method = 'GET', body = null, timeoutMs = 12000 } = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, origin);
    const payload = body === null ? null : JSON.stringify(body);
    const req = httpsRequest({
      hostname: url.hostname,
      port: url.port || 443,
      path: url.pathname + url.search,
      method,
      headers: {
        ...LOGIN_HEADERS,
        ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
      },
    }, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (d) => { data += d; });
      res.on('end', () => {
        try { resolve({ status: res.statusCode, json: JSON.parse(data || '{}'), raw: data }); }
        catch { resolve({ status: res.statusCode, json: null, raw: data }); }
      });
    });
    req.setTimeout(timeoutMs, () => { req.destroy(new Error('请求官方网关超时')); });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

/** 进行中的登录会话：state → 轮询任务。只允许一个（个人 NAS 场景）。 */
let loginSession = null;

async function startLogin() {
  const gw = loginGateway();
  const res = await gatewayJson(gw.origin, '/v2/plugin/auth/state?platform=workbuddy', {
    method: 'POST', body: {},
  });
  const data = res.json?.data;
  if (res.json?.code !== 0 || !data?.state || !data?.authUrl) {
    throw new Error(`申请登录链接失败：HTTP ${res.status} ${String(res.raw).slice(0, 200)}`);
  }

  const session = {
    state: data.state,
    authUrl: data.authUrl,
    origin: gw.origin,
    label: gw.label,
    startedAt: Date.now(),
    status: 'waiting',   // waiting | done | error | expired
    message: '等待你在浏览器里完成登录…',
    timer: null,
    auth: null,
  };

  /** 轮询：直到拿到令牌 / 超时 / 被取消。 */
  const poll = async () => {
    if (loginSession !== session || session.status !== 'waiting') return;
    // 10 分钟没完成就当过期（官方 sign-in 超时也是这个量级）
    if (Date.now() - session.startedAt > 10 * 60 * 1000) {
      session.status = 'expired';
      session.message = '登录超时，请重新发起';
      return;
    }
    try {
      const r = await gatewayJson(
        session.origin,
        `/v2/plugin/auth/token?state=${encodeURIComponent(session.state)}`,
      );
      const payload = r.json || {};
      if (payload.code === 0 && payload.data && (payload.data.accessToken || payload.data.token)) {
        const d = payload.data;
        const auth = {
          accessToken: d.accessToken || d.token,
          refreshToken: d.refreshToken || '',
          domain: d.domain || (session.origin.includes('workbuddy.ai') ? 'www.workbuddy.ai' : ''),
          expiresAt: Number(d.expiresAt || 0) || (Date.now() + Number(d.expiresIn || 0) * 1000),
          refreshExpiresAt: Number(d.refreshExpiresAt || 0)
            || (Date.now() + Number(d.refreshExpiresIn || 0) * 1000),
        };
        if (!auth.domain) {
          // 从 JWT 的 iss 兜底推断域名
          try {
            const claims = JSON.parse(Buffer.from(auth.accessToken.split('.')[1], 'base64url').toString('utf8'));
            auth.domain = String(claims.iss || '').replace(/^https?:\/\//, '');
          } catch { /* 无 iss 就留空，桥会按 endpoint 判断 */ }
        }
        session.auth = auth;
        session.status = 'done';
        session.message = '登录成功，凭据已更新';
        return;
      }
      // 11217 = 还在等用户操作，继续轮询；其余 code 视为失败
      if (payload.code !== 11217 && payload.code !== 0) {
        session.status = 'error';
        session.message = `登录失败：${payload.code} ${payload.msg || ''}`.trim();
        return;
      }
    } catch (e) {
      // 网络抖动不终止轮询，下一轮再试
      session.message = `轮询中（${e.message}）`;
    }
    session.timer = setTimeout(poll, 2000);
  };

  loginSession = session;
  session.timer = setTimeout(poll, 1500);
  return {
    authUrl: session.authUrl,
    state: session.state,
    label: session.label,
    expiresInSec: 600,
  };
}

function loginStatus() {
  if (!loginSession) return { active: false };
  const s = loginSession;
  return {
    active: s.status === 'waiting',
    status: s.status,
    message: s.message,
    authUrl: s.authUrl,
    label: s.label,
    elapsedSec: Math.round((Date.now() - s.startedAt) / 1000),
  };
}

function cancelLogin() {
  if (loginSession?.timer) clearTimeout(loginSession.timer);
  loginSession = null;
}

/* ── 会话 ────────────────────────────────────────────────────────────── */

const COOKIE = 'wb_console';

function signSession(exp) {
  return createHmac('sha256', sessionSecret()).update(`v1.${exp}`).digest('base64url');
}

function makeSession(maxAgeSec = 7 * 86400) {
  const exp = Date.now() + maxAgeSec * 1000;
  return `v1.${exp}.${signSession(exp)}`;
}

function validSession(cookieHeader) {
  if (!cookieHeader) return false;
  const raw = cookieHeader.split(';').map((s) => s.trim()).find((s) => s.startsWith(`${COOKIE}=`));
  if (!raw) return false;
  const value = decodeURIComponent(raw.slice(COOKIE.length + 1));
  const [v, expStr, sig] = value.split('.');
  if (v !== 'v1' || !expStr || !sig) return false;
  const exp = Number(expStr);
  if (!Number.isFinite(exp) || Date.now() > exp) return false;
  const expect = signSession(exp);
  const a = Buffer.from(sig);
  const b = Buffer.from(expect);
  return a.length === b.length && timingSafeEqual(a, b);
}

/* ── HTTP 工具 ────────────────────────────────────────────────────────── */

function send(res, status, body, headers = {}) {
  const isJson = typeof body === 'object' && body !== null;
  const payload = isJson ? JSON.stringify(body) : String(body);
  res.writeHead(status, {
    'Content-Type': isJson ? 'application/json; charset=utf-8' : 'text/html; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    ...headers,
  });
  res.end(payload);
}

function readBody(req, limitBytes = 2 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limitBytes) { reject(new Error('请求体过大')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

const compareSecret = (a, b) => {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && timingSafeEqual(x, y);
};

/*
 * 登录失败限速 —— 防止局域网内有人把口令穷举出来。
 *
 * 为什么必须有：这个控制台默认监听 0.0.0.0，同一局域网内任何人都能访问；
 * 而个人项目常见的是 6~8 位短口令，无限制重试下几分钟就能撞开。口令一旦
 * 被破，攻击者能拿到所有 API Key、改配置、甚至替换凭据。
 *
 * 策略（按来源 IP 计）：
 *   · 连续失败 5 次 → 锁 60 秒；之后每次再失败，锁定时长翻倍，上限 15 分钟；
 *   · 成功登录即清零。
 * 只锁「登录尝试」，不影响已登录会话 —— 免得自己被自己锁在门外。
 */
const LOGIN_MAX_FAILS = 5;
const LOGIN_LOCK_BASE_MS = 60 * 1000;
const LOGIN_LOCK_MAX_MS = 15 * 60 * 1000;
const loginAttempts = new Map();   // ip -> { fails, lockedUntil }

function clientIp(req) {
  // 本地回环/直连时 remoteAddress 就是真实来源；反代场景依赖 X-Forwarded-For
  const xf = req.headers['x-forwarded-for'];
  const first = Array.isArray(xf) ? xf[0] : (typeof xf === 'string' ? xf.split(',')[0] : '');
  return String(first || req.socket?.remoteAddress || 'unknown').trim();
}

/** 返回剩余锁定毫秒数；0 表示可以尝试。 */
function loginLockRemaining(ip) {
  const rec = loginAttempts.get(ip);
  if (!rec) return 0;
  const left = (rec.lockedUntil || 0) - Date.now();
  return left > 0 ? left : 0;
}

function recordLoginFailure(ip) {
  const rec = loginAttempts.get(ip) || { fails: 0, lockedUntil: 0 };
  rec.fails += 1;
  if (rec.fails >= LOGIN_MAX_FAILS) {
    const over = rec.fails - LOGIN_MAX_FAILS;
    const lock = Math.min(LOGIN_LOCK_BASE_MS * 2 ** over, LOGIN_LOCK_MAX_MS);
    rec.lockedUntil = Date.now() + lock;
  }
  loginAttempts.set(ip, rec);
}

function clearLoginFailures(ip) {
  loginAttempts.delete(ip);
}

// 定期清掉过期记录，避免 Map 无界增长（攻击者可以不断换 IP）
setInterval(() => {
  const now = Date.now();
  for (const [ip, rec] of loginAttempts) {
    if ((rec.lockedUntil || 0) < now - 60 * 60 * 1000 && rec.fails < LOGIN_MAX_FAILS) {
      loginAttempts.delete(ip);
    }
  }
}, 10 * 60 * 1000).unref?.();


/* ── 页面 ────────────────────────────────────────────────────────────── */

const LOGIN_HTML = /* html */`<!doctype html>
<html lang="zh-CN"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI Gateway 控制台 · 登录</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin:0; min-height:100vh; display:grid; place-items:center;
    font:15px/1.5 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif;
    background:radial-gradient(1200px 600px at 50% -10%,#1b2a4a,#0b0f16 60%); color:#e6edf7; }
  .card { width:min(360px,92vw); padding:32px 28px; border-radius:16px;
    background:#11161f; border:1px solid #1f2836; box-shadow:0 20px 60px #0008; }
  h1 { margin:0 0 4px; font-size:19px; font-weight:650; letter-spacing:.2px; }
  p.sub { margin:0 0 22px; color:#7d8ba1; font-size:13px; }
  label { display:block; font-size:12px; color:#8b9ab0; margin:0 0 6px; }
  input { width:100%; padding:11px 12px; border-radius:9px; border:1px solid #26303f;
    background:#0b0f16; color:#e6edf7; font:inherit; outline:none; }
  input:focus { border-color:#3d6fd4; box-shadow:0 0 0 3px #3d6fd422; }
  button { width:100%; margin-top:16px; padding:11px; border-radius:9px; border:0;
    background:#3d6fd4; color:#fff; font:inherit; font-weight:600; cursor:pointer; }
  button:hover { background:#4b7de3; }
  .err { margin-top:12px; color:#ff7b72; font-size:13px; min-height:18px; }
</style></head><body>
<form class="card" method="post" action="/api/login">
  <h1>AI Gateway 控制台</h1>
  <p class="sub">管理模型代理、凭据与访问密钥</p>
  <label for="pwd">管理口令</label>
  <input id="pwd" name="password" type="password" autocomplete="current-password" autofocus required>
  <button type="submit">登录</button>
  <div class="err" id="err"></div>
</form>
<script>
  const q = new URLSearchParams(location.search);
  if (q.get('err')) document.getElementById('err').textContent = q.get('err');
</script>
</body></html>`;

const APP_HTML = /* html */`<!doctype html>
<html lang="zh-CN"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI Gateway 控制台</title>
<style>
  :root { color-scheme: dark;
    --bg:#0b0f16; --panel:#11161f; --line:#1f2836; --line2:#26303f;
    --fg:#e6edf7; --dim:#7d8ba1; --accent:#3d6fd4; --ok:#3fb950; --warn:#d29922; --err:#f85149; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--fg);
    font:15px/1.55 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif; }
  header { position:sticky; top:0; z-index:10; display:flex; align-items:center; gap:14px;
    padding:14px 22px; background:#0b0f16e6; backdrop-filter:blur(8px); border-bottom:1px solid var(--line); }
  header h1 { margin:0; font-size:16px; font-weight:650; }
  .pill { font-size:12px; padding:3px 9px; border-radius:999px; border:1px solid var(--line2); color:var(--dim); }
  .pill.ok { color:var(--ok); border-color:#1e4429; background:#0d1f13; }
  .pill.bad { color:var(--err); border-color:#4a1f1f; background:#1f0d0d; }
  header .spacer { flex:1; }
  main { max-width:1080px; margin:0 auto; padding:22px; display:grid; gap:18px; }
  .grid { display:grid; gap:14px; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); }
  .card { background:var(--panel); border:1px solid var(--line); border-radius:14px; padding:18px; }
  .card h2 { margin:0 0 14px; font-size:14px; font-weight:620; color:#c3cede; }
  .kpi .label { font-size:12px; color:var(--dim); margin-bottom:6px; }
  .kpi .value { font-size:23px; font-weight:650; letter-spacing:.3px; }
  .kpi .hint { font-size:12px; color:var(--dim); margin-top:4px; }
  table { width:100%; border-collapse:collapse; font-size:13.5px; }
  th,td { text-align:left; padding:9px 8px; border-bottom:1px solid var(--line); }
  th { color:var(--dim); font-weight:500; font-size:12px; }
  tr:last-child td { border-bottom:0; }
  code, .mono { font-family:ui-monospace,Consolas,monospace; font-size:12.5px; }
  .copy { display:inline-flex; align-items:center; gap:8px; background:#0b0f16;
    border:1px solid var(--line2); border-radius:8px; padding:7px 10px; max-width:100%; }
  .copy span { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  button { padding:8px 13px; border-radius:8px; border:1px solid var(--line2);
    background:#161d28; color:var(--fg); font:inherit; font-size:13px; cursor:pointer; }
  button:hover { border-color:#33415a; }
  button.primary { background:var(--accent); border-color:var(--accent); font-weight:600; }
  button.primary:hover { background:#4b7de3; }
  button.danger { color:#ff9b93; border-color:#4a1f1f; }
  input[type=text], input[type=password], textarea { width:100%; padding:9px 11px; border-radius:8px;
    border:1px solid var(--line2); background:#0b0f16; color:var(--fg); font:inherit; outline:none; }
  input:focus, textarea:focus { border-color:var(--accent); box-shadow:0 0 0 3px #3d6fd422; }
  textarea { resize:vertical; min-height:74px; font-family:ui-monospace,monospace; font-size:12.5px; }
  .row { display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
  .muted { color:var(--dim); font-size:12.5px; }
  .warn { color:var(--warn); }
  .err { color:var(--err); }
  .drop { border:1.5px dashed var(--line2); border-radius:12px; padding:22px; text-align:center;
    color:var(--dim); font-size:13px; cursor:pointer; transition:.15s; }
  .drop:hover, .drop.over { border-color:var(--accent); color:#9fb6e0; background:#111a2b; }
  .bars { display:grid; gap:6px; margin-top:6px; }
  .bar { display:grid; grid-template-columns:96px 1fr 64px; gap:10px; align-items:center; font-size:12.5px; }
  .bar .track { height:6px; border-radius:4px; background:#0b0f16; overflow:hidden; }
  .bar .fill { height:100%; background:linear-gradient(90deg,#3d6fd4,#5b8ef0); }
  .hide { display:none !important; }
  .toast { position:fixed; left:50%; bottom:26px; transform:translateX(-50%) translateY(20px);
    background:#182130; border:1px solid var(--line2); color:var(--fg); padding:11px 17px;
    border-radius:10px; font-size:13.5px; opacity:0; transition:.22s; pointer-events:none; z-index:50; }
  .toast.show { opacity:1; transform:translateX(-50%) translateY(0); }
  .toast.err { border-color:#4a1f1f; color:#ff9b93; }
  .btnlink { display:inline-flex; align-items:center; padding:8px 13px; border-radius:8px;
    border:1px solid var(--line2); color:var(--fg); text-decoration:none; font-size:13px; }
  .btnlink:hover { border-color:#33415a; background:#161d28; }
</style></head><body>

<header>
  <h1>AI Gateway 控制台</h1>
  <span class="pill" id="health">检查中…</span>
  <span class="spacer"></span>
  <button id="btnRefresh">刷新</button>
  <button class="danger" id="btnLogout">退出</button>
</header>

<main>
  <div class="grid">
    <div class="card kpi">
      <div class="label">账号</div>
      <div class="value mono" id="kAccount" style="font-size:14px">—</div>
      <div class="hint" id="kEndpoint">—</div>
    </div>
    <div class="card kpi">
      <div class="label">剩余额度</div>
      <div class="value" id="kQuota">—</div>
      <div class="hint" id="kQuotaHint">—</div>
    </div>
    <div class="card kpi">
      <div class="label">今日调用</div>
      <div class="value" id="kToday">—</div>
      <div class="hint" id="kTodayHint">—</div>
    </div>
    <div class="card kpi">
      <div class="label">令牌到期</div>
      <div class="value" id="kExpiry">—</div>
      <div class="hint" id="kExpiryHint">—</div>
    </div>
  </div>

  <div class="card">
    <h2>接入地址</h2>
    <div class="muted" style="margin-bottom:10px">把这一个地址和任意一把 API Key 填进客户端的「自定义 OpenAI 服务商」即可。</div>
    <div class="row"><div class="copy"><span class="mono" id="baseUrl">—</span></div>
      <button data-copy="baseUrl">复制</button></div>
  </div>

  <div class="card">
    <h2>API Key</h2>
    <div class="muted" style="margin-bottom:12px">每台设备一把，出问题时单独删除，不影响其他设备。改动会自动重启桥。</div>
    <table><thead><tr><th>名称</th><th>Key</th><th>创建时间</th><th style="width:70px"></th></tr></thead>
      <tbody id="keyRows"></tbody></table>
    <div class="row" style="margin-top:12px">
      <input type="text" id="newKeyLabel" placeholder="设备名，例如 ipad / 客厅电视" style="flex:1;min-width:180px">
      <button class="primary" id="btnAddKey">生成 Key</button>
    </div>
  </div>

  <div class="card">
    <h2 style="display:flex;align-items:center;gap:10px">
      模型
      <span class="muted" id="modelCount" style="font-weight:400"></span>
      <span style="flex:1"></span>
      <button id="btnModelMore" class="muted" style="padding:4px 10px;font-size:12px">显示全部</button>
    </h2>
    <table><thead><tr><th>模型</th><th>倍率</th><th>上下文</th><th>标记</th></tr></thead>
      <tbody id="modelRows"></tbody></table>
    <div class="muted" style="margin-top:10px">倍率 0 表示当前不计费。上游目录会漏列部分模型，桥会自动补齐。</div>
  </div>

  <div class="card">
    <h2>近 7 天用量</h2>
    <div class="bars" id="usageBars"></div>
    <div class="muted" id="usageSummary" style="margin-top:12px">—</div>
  </div>

  <div class="card">
    <h2>登录上游账号</h2>
    <div class="muted" style="margin-bottom:12px">
      点下面的按钮，会打开 <b>WorkBuddy 官方登录页</b>。你在那里输入账号密码或扫码即可 ——
      密码只发给官方服务器，<b>不经过这台 NAS</b>。登录完成后凭据会自动写入并重启桥。
    </div>

    <div id="loginIdle">
      <button class="primary" id="btnLogin">打开官方登录页</button>
      <span class="muted" id="loginHint"></span>
    </div>

    <div id="loginActive" class="hide">
      <div class="row" style="margin-bottom:10px">
        <span class="pill" id="loginState">等待登录…</span>
        <span class="muted" id="loginElapsed"></span>
      </div>
      <div class="row" style="margin-bottom:10px">
        <div class="copy" style="flex:1"><span class="mono" id="loginUrl">—</span></div>
        <button data-copy="loginUrl">复制链接</button>
      </div>
      <div class="row">
        <a id="loginOpen" class="btnlink" href="#" target="_blank" rel="noopener noreferrer">在这台设备打开</a>
        <button id="btnLoginCancel" class="danger">取消</button>
      </div>
      <div class="muted" style="margin-top:10px">
        用手机或另一台电脑打开这个链接也可以，登录完这里会自动继续。
      </div>
    </div>
  </div>

  <div class="card">
    <h2>或：手动上传凭据</h2>
    <div class="muted" style="margin-bottom:12px">
      不方便走网页登录时，可以上传 WorkBuddy 桌面端的 <code>workbuddy-desktop.info</code>，
      或已导出的 <code>auth.json</code>。如果上传的是加密的 .info，需要下面那把「AtRest 密钥」。
    </div>
    <div class="drop" id="drop">点这里选择文件，或把文件拖进来</div>
    <input type="file" id="file" class="hide" accept=".json,.info,application/json">
    <textarea id="paste" placeholder="也可以直接粘贴 JSON 内容…" style="margin-top:10px"></textarea>
    <div class="row" style="margin-top:10px">
      <button class="primary" id="btnUpload">上传并应用</button>
      <span class="muted" id="credState">—</span>
    </div>
    <div id="credMsg" class="muted" style="margin-top:8px"></div>
  </div>

  <div class="card">
    <h2>设置</h2>
    <div class="row" style="margin-bottom:12px">
      <input type="password" id="atrestKey" placeholder="AtRest 密钥（Base64，44 字符）" style="flex:1;min-width:220px">
      <button id="btnSaveAtrest">保存密钥</button>
    </div>
    <div class="muted" style="margin-bottom:14px">
      密钥来自安装了 WorkBuddy 的那台电脑，用 <code>export-auth.mjs --print-key</code> 取得。
      它只用于解密上传的 .info；不填就只能上传已解密的 auth.json。
    </div>
    <div class="row">
      <input type="password" id="newPwd" placeholder="新的管理口令（至少 4 位）" style="flex:1;min-width:200px">
      <button id="btnSavePwd">修改口令</button>
    </div>
    <div class="row" style="margin-top:16px">
      <input type="text" id="maxConc" placeholder="并发上限（1=串行；0=不限）" style="flex:1;min-width:200px">
      <button id="btnSaveConc">保存并发</button>
    </div>
    <div class="muted" style="margin-top:8px">
      上游对单账号是<b>串行</b>处理的，所以并发设 1 通常最快也最稳（其他请求在本地排队，
      不会因为撞上游限制而失败）。设 0 会一次性全推给上游，长对话时容易触发 429。
    </div>
  </div>

  <div class="card">
    <h2>桥日志</h2>
    <pre class="mono" id="logBox" style="margin:0;max-height:260px;overflow:auto;color:#9aa8bd;white-space:pre-wrap"></pre>
  </div>
</main>

<div class="toast" id="toast"></div>

<script>
const $ = (id) => document.getElementById(id);
const toast = (msg, isErr) => {
  const t = $('toast');
  t.textContent = msg;
  t.className = 'toast show' + (isErr ? ' err' : '');
  clearTimeout(t._h);
  t._h = setTimeout(() => { t.className = 'toast'; }, 2600);
};
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

async function api(path, opts) {
  const r = await fetch(path, opts);
  if (r.status === 401) { location.href = '/'; throw new Error('未登录'); }
  return r.json();
}

let state = { keys: [], baseUrl: '' };
/** 模型表是否展开全部（默认只看精选） */
let showAllModels = false;

function render() {
  /* /api/state 返回的是**扁平**结构（bridgeUp/account/quota… 直接在顶层），
     早先这里写成 state.status 取了个不存在的字段，导致整页除了 keys 全是空。 */
  const s = state;
  const account = s.account || '—';
  $('kAccount').textContent = account ? account.slice(0, 8) + '…' : '—';
  $('kAccount').title = account;
  $('kEndpoint').textContent = s.endpoint || (s.credential && s.credential.domain) || '—';

  const q = s.quota;
  $('kQuota').textContent = q && typeof q.total === 'number' ? q.total : '—';
  $('kQuotaHint').textContent = q && Array.isArray(q.packages) && q.packages.length
    ? q.packages.map(p => p.name + ' ' + p.remain + '/' + p.size).slice(0, 2).join(' · ')
    : '查询不到（可能未登录或接口变化）';

  const u = s.usage || {};
  const today = (u.days || []).find(d => d.day === new Date(Date.now() + 8*3600*1000).toISOString().slice(0,10));
  $('kToday').textContent = today ? today.calls : '0';
  $('kTodayHint').textContent = today
    ? '消耗 ' + (Math.round((today.credit || 0) * 100) / 100) + ' 分 · 失败 ' + (s.failedToday ?? 0)
    : '还没有调用';

  const exp = s.credential && s.credential.expiresAt;
  if (exp) {
    const days = Math.floor((exp - Date.now()) / 86400000);
    $('kExpiry').textContent = days + ' 天';
    $('kExpiry').className = 'value' + (days < 7 ? ' warn' : '');
    $('kExpiryHint').textContent = new Date(exp).toLocaleString('zh-CN');
  } else {
    $('kExpiry').textContent = '—';
    $('kExpiryHint').textContent = '未知';
  }

  const h = $('health');
  const cc = s.concurrency;
  if (!s.bridgeUp) {
    h.textContent = '桥未运行'; h.className = 'pill bad';
  } else if (cc && cc.queued > 0) {
    // 有请求在排队：明确说出来，否则用户只觉得"慢"却不知道为什么
    h.textContent = \`运行中 · 排队 \${cc.queued}\`; h.className = 'pill';
  } else if (cc && cc.active > 0) {
    h.textContent = \`运行中 · \${cc.active}/\${cc.limit} 在跑\`; h.className = 'pill ok';
  } else {
    h.textContent = '运行中'; h.className = 'pill ok';
  }

  $('baseUrl').textContent = state.baseUrl || '—';

  $('keyRows').innerHTML = state.keys.length ? state.keys.map(k => \`
    <tr><td>\${esc(k.label || '未命名')}</td>
      <td><span class="mono">\${esc(k.masked)}</span></td>
      <td class="muted">\${k.createdAt ? new Date(k.createdAt).toLocaleDateString('zh-CN') : '—'}</td>
      <td><button class="danger" data-del="\${esc(k.id)}">删除</button></td></tr>\`).join('')
    : '<tr><td colspan="4" class="muted">还没有 API Key。生成一把再接入客户端。</td></tr>';

  /*
   * 模型表默认只显示「值得选」的那几个，其余折叠。
   * 37 行全铺=页面被撑长，反而看不到下面的凭据/设置 —— 而用户日常只需要
   * 免费档和主力模型。排序：免费优先，其次倍率升序（便宜的在前）。
   */
  const allModels = s.models || [];
  const ranked = [...allModels].sort((a, b) => {
    const fa = a.credits === 0 ? 0 : 1;
    const fb = b.credits === 0 ? 0 : 1;
    if (fa !== fb) return fa - fb;
    return (a.credits ?? 999) - (b.credits ?? 999);
  });
  const shown = showAllModels ? ranked : ranked.slice(0, 6);
  $('modelCount').textContent = allModels.length ? '(' + allModels.length + ')' : '';
  $('btnModelMore').textContent = showAllModels ? '收起' : '显示全部';
  $('btnModelMore').style.display = allModels.length > 6 ? '' : 'none';
  $('modelRows').innerHTML = shown.length ? shown.map(m => \`
    <tr><td class="mono">\${esc(m.id)}</td>
      <td>\${m.credits === 0 ? '<span style="color:#3fb950">免费</span>' : (m.credits ?? '—')}</td>
      <td class="muted">\${m.context_window ? Math.round(m.context_window/1000)+'k' : '—'}</td>
      <td class="muted">\${esc(m.badge || '')}</td></tr>\`).join('')
    : '<tr><td colspan="4" class="muted">读不到模型列表</td></tr>';

  const days = (u.days || []).slice(-7);
  const max = Math.max(1, ...days.map(d => d.credit || 0));
  $('usageBars').innerHTML = days.length ? days.map(d => \`
    <div class="bar"><span class="muted">\${esc(d.day.slice(5))}</span>
      <span class="track"><span class="fill" style="width:\${Math.round((d.credit||0)/max*100)}%"></span></span>
      <span class="muted">\${Math.round((d.credit||0)*100)/100} 分</span></div>\`).join('')
    : '<div class="muted">还没有数据</div>';

  const t = u.total || {};
  $('usageSummary').textContent = t.calls
    ? \`共 \${t.calls} 次调用 · \${Math.round((t.credit||0)*100)/100} 分 · 失败 \${t.failed || 0} 次\`
    : '还没有数据';

  const cs = $('credState');
  if (s.credential) {
    cs.className = 'muted';
    cs.textContent = '已配置 · ' + (s.credential.domain || '未知域名');
  } else {
    cs.className = 'err';
    cs.textContent = '还没有凭据';
  }

  $('logBox').textContent = (s.log || []).join('\\n') || '（暂无日志）';
  $('atrestKey').placeholder = s.hasAtrestKey ? '已保存（重新填写可替换）' : 'AtRest 密钥（Base64，44 字符）';
  $('maxConc').placeholder = '并发上限（当前 ' + (s.maxConcurrency ?? 1) + '）';
}

async function load() {
  state = await api('/api/state');
  render();
}

$('btnRefresh').onclick = () => load().then(() => toast('已刷新'));
$('btnModelMore').onclick = () => { showAllModels = !showAllModels; render(); };
$('btnLogout').onclick = async () => { await fetch('/api/logout', { method: 'POST' }); location.href = '/'; };

$('btnAddKey').onclick = async () => {
  const label = $('newKeyLabel').value.trim();
  const r = await api('/api/keys', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ label }),
  });
  if (!r.ok) return toast(r.error || '生成失败', true);
  $('newKeyLabel').value = '';
  await load();
  prompt('这是新 Key 的明文，只显示这一次。复制保存：', r.key);
};

document.addEventListener('click', async (e) => {
  const del = e.target.closest('[data-del]');
  if (del) {
    if (!confirm('删除后该设备立即无法访问，确定？')) return;
    const r = await api('/api/keys/' + encodeURIComponent(del.dataset.del), { method: 'DELETE' });
    if (!r.ok) return toast(r.error || '删除失败', true);
    await load(); toast('已删除');
    return;
  }
  const cp = e.target.closest('[data-copy]');
  if (cp) {
    const text = $(cp.dataset.copy).textContent;
    try { await navigator.clipboard.writeText(text); toast('已复制'); }
    catch { toast('复制失败，请手动选中', true); }
  }
});

$('drop').onclick = () => $('file').click();
$('drop').ondragover = (e) => { e.preventDefault(); $('drop').classList.add('over'); };
$('drop').ondragleave = () => $('drop').classList.remove('over');
$('drop').ondrop = (e) => {
  e.preventDefault(); $('drop').classList.remove('over');
  const f = e.dataTransfer.files[0];
  if (f) readFile(f);
};
$('file').onchange = (e) => { const f = e.target.files[0]; if (f) readFile(f); };

function readFile(f) {
  const r = new FileReader();
  r.onload = () => { $('paste').value = r.result; $('drop').textContent = '已读取：' + f.name; };
  r.readAsText(f);
}

$('btnUpload').onclick = async () => {
  const raw = $('paste').value.trim();
  if (!raw) return toast('先选文件或粘贴内容', true);
  const r = await api('/api/credential', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ raw }),
  });
  const box = $('credMsg');
  if (!r.ok) { box.className = 'err'; box.textContent = r.error; return toast('应用失败', true); }
  box.className = 'muted';
  box.textContent = '已应用 · 账号 ' + (r.account || '?') + ' · ' + (r.endpoint || '');
  $('paste').value = '';
  toast('凭据已更新，桥已重启');
  await load();
};

/* ── WorkBuddy 官方网页登录 ─────────────────────────────────────────── */

let loginPoll = null;

function stopLoginPoll() {
  if (loginPoll) { clearInterval(loginPoll); loginPoll = null; }
}

function showLoginActive(info) {
  $('loginIdle').classList.add('hide');
  $('loginActive').classList.remove('hide');
  $('loginUrl').textContent = info.authUrl;
  $('loginOpen').href = info.authUrl;
  $('loginState').textContent = '等待登录…';
  $('loginState').className = 'pill';
  $('loginElapsed').textContent = info.label ? '（' + info.label + '）' : '';
}

function showLoginIdle(hint) {
  stopLoginPoll();
  $('loginActive').classList.add('hide');
  $('loginIdle').classList.remove('hide');
  $('loginHint').textContent = hint || '';
}

$('btnLogin').onclick = async () => {
  $('btnLogin').disabled = true;
  try {
    const r = await api('/api/login/start', { method: 'POST' });
    if (!r.ok) { toast(r.error || '发起登录失败', true); return; }
    showLoginActive(r);
    // 立刻在新标签打开（部分浏览器会拦自动弹窗，所以下面还给了显式链接）
    try { window.open(r.authUrl, '_blank', 'noopener'); } catch (e) { /* 被拦就算了 */ }
    stopLoginPoll();
    loginPoll = setInterval(async () => {
      const s = await api('/api/login/status').catch(() => null);
      if (!s) return;
      if (s.status === 'waiting') {
        $('loginElapsed').textContent = '已等待 ' + s.elapsedSec + ' 秒';
        return;
      }
      stopLoginPoll();
      if (s.status === 'done') {
        $('loginState').textContent = '登录成功';
        $('loginState').className = 'pill ok';
        toast('登录成功，凭据已更新');
        await load();
        setTimeout(() => showLoginIdle('已通过官方网页登录更新凭据'), 1500);
      } else {
        $('loginState').textContent = s.status === 'expired' ? '已超时' : '失败';
        $('loginState').className = 'pill bad';
        toast(s.message || '登录未完成', true);
        setTimeout(() => showLoginIdle(s.message || ''), 2000);
      }
    }, 2000);
  } finally {
    $('btnLogin').disabled = false;
  }
};

$('btnLoginCancel').onclick = async () => {
  await fetch('/api/login/cancel', { method: 'POST' }).catch(() => {});
  showLoginIdle('已取消');
};

$('btnSaveAtrest').onclick = async () => {
  const key = $('atrestKey').value.trim();
  if (!key) return toast('请填写密钥', true);
  const r = await api('/api/atrest-key', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ key }),
  });
  if (!r.ok) return toast(r.error || '保存失败', true);
  $('atrestKey').value = '';
  toast('已保存');
  await load();
};

$('btnSavePwd').onclick = async () => {
  const pwd = $('newPwd').value;
  if (pwd.length < 4) return toast('口令至少 4 位', true);
  const r = await api('/api/password', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: pwd }),
  });
  if (!r.ok) return toast(r.error || '修改失败', true);
  $('newPwd').value = '';
  toast('口令已修改，请重新登录');
  setTimeout(() => { location.href = '/'; }, 1200);
};

$('btnSaveConc').onclick = async () => {
  const raw = $('maxConc').value.trim();
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 0 || n > 16) {
    return toast('并发请填 0~16 的整数', true);
  }
  const r = await api('/api/concurrency', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ maxConcurrency: n }),
  });
  if (!r.ok) return toast(r.error || '保存失败', true);
  $('maxConc').value = '';
  toast('已保存，桥已重启');
  await load();
};

load();
setInterval(load, 20000);
</script>
</body></html>`;

/* ── 路由 ────────────────────────────────────────────────────────────── */

async function buildState() {
  const auth = readAuthSummary();
  const health = await bridgeGet('/health');
  const up = !!(health && health.status === 200 && health.json && health.json.ok);

  let quota = null;
  let models = [];
  let usage = null;

  if (up) {
    const q = await bridgeGet('/v1/quota');
    quota = q && q.json && q.json.ok ? q.json : null;
    const m = await bridgeGet('/v1/models?all=1');
    models = m && m.json && Array.isArray(m.json.data) ? m.json.data : [];
    const u = await bridgeGet('/v1/usage?days=7');
    usage = u && u.json && u.json.ok ? u.json : null;
  }

  const todayKey = new Date(Date.now() + 8 * 3600 * 1000).toISOString().slice(0, 10);
  /* 今日失败数：账本只给最近若干条失败，按 8 小时时区折算到今天 */
  const todayStart = new Date(`${todayKey}T00:00:00+08:00`).getTime();
  const failedToday = (usage?.failures || []).filter((f) => Number(f.t) >= todayStart).length;

  return {
    bridgeUp: up,
    account: health?.json?.auth?.userId || auth?.account || '',
    endpoint: health?.json?.auth?.endpoint || '',
    quota,
    models,
    usage,
    failedToday,
    credential: auth,
    hasAtrestKey: !!config.atrestKey,
    // 桥的实时并发水位：active 在跑、queued 在排队 —— 让「慢」有解释
    concurrency: health?.json?.process?.concurrency || null,
    maxConcurrency: config.maxConcurrency ?? 1,
    log: bridgeLog.slice(-60),
  };
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const path = url.pathname;
  const authed = validSession(req.headers.cookie);

  try {
    if (path === '/' && req.method === 'GET') {
      if (!authed) return send(res, 200, LOGIN_HTML);
      return send(res, 200, APP_HTML);
    }

    if (path === '/api/login' && req.method === 'POST') {
      // 先看是否处于锁定状态：锁定期内连口令都不比对，直接拒绝
      const ip = clientIp(req);
      const locked = loginLockRemaining(ip);
      if (locked > 0) {
        const sec = Math.ceil(locked / 1000);
        const wantsJson0 = (req.headers['content-type'] || '').includes('application/json');
        if (wantsJson0) {
          return send(res, 429, { ok: false, error: `尝试过于频繁，请 ${sec} 秒后再试` }, { 'Retry-After': String(sec) });
        }
        return send(res, 302, '', { Location: '/?err=' + encodeURIComponent(`尝试过于频繁，请 ${sec} 秒后再试`) });
      }
      const body = await readBody(req);
      const wantsJson = (req.headers['content-type'] || '').includes('application/json');
      let pwd = '';
      if (wantsJson) {
        pwd = JSON.parse(body || '{}').password || '';
      } else {
        pwd = new URLSearchParams(body).get('password') || '';
      }
      if (!compareSecret(pwd, config.consolePassword)) {
        recordLoginFailure(clientIp(req));
        if (wantsJson) return send(res, 401, { ok: false, error: '口令不对' });
        return send(res, 302, '', { Location: '/?err=' + encodeURIComponent('口令不对') });
      }
      clearLoginFailures(clientIp(req));
      const cookie = `${COOKIE}=${encodeURIComponent(makeSession())}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${7 * 86400}`;
      /*
       * 浏览器原生表单提交（非 JSON）必须**跳转**回首页。
       * 早先这里无差别返回 {"ok":true}，于是用表单登录时浏览器停在了
       * /api/login 的原始 JSON 上 —— 看起来像"点登录没反应"，其实已经登录成功。
       */
      if (!wantsJson) return send(res, 302, '', { Location: '/', 'Set-Cookie': cookie });
      return send(res, 200, { ok: true }, { 'Set-Cookie': cookie });
    }

    if (path === '/api/logout' && req.method === 'POST') {
      return send(res, 200, { ok: true }, {
        'Set-Cookie': `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`,
      });
    }

    /* 以下都要登录 */
    if (!authed) return send(res, 401, { ok: false, error: '未登录' });

    if (path === '/api/state' && req.method === 'GET') {
      const state = await buildState();
      const host = req.headers.host || '';
      const hostname = host.split(':')[0] || 'localhost';
      return send(res, 200, {
        ...state,
        baseUrl: `http://${hostname}${BRIDGE_PORT === 80 ? '' : ':' + BRIDGE_PORT}/v1`,
        keys: config.clientKeys.map((k) => ({
          id: k.id,
          label: k.label,
          masked: k.key.slice(0, 6) + '…' + k.key.slice(-4),
          createdAt: k.createdAt,
        })),
      });
    }

    /* ── WorkBuddy 官方网页登录 ──────────────────────────────────────── */

    if (path === '/api/login/start' && req.method === 'POST') {
      try {
        cancelLogin();
        const info = await startLogin();
        return send(res, 200, { ok: true, ...info });
      } catch (e) {
        return send(res, 502, { ok: false, error: e.message });
      }
    }

    if (path === '/api/login/status' && req.method === 'GET') {
      const s = loginStatus();
      // 轮询到成功后，在这里落地凭据并重启桥（只做一次）
      if (loginSession && loginSession.status === 'done' && !loginSession.persisted) {
        loginSession.persisted = true;
        try {
          saveJson(AUTH_PATH, { auth: loginSession.auth });
          await restartBridge();
          loginSession.message = '登录成功，桥已重启';
        } catch (e) {
          loginSession.message = `登录成功但写入失败：${e.message}`;
        }
      }
      return send(res, 200, { ok: true, ...s });
    }

    if (path === '/api/login/cancel' && req.method === 'POST') {
      cancelLogin();
      return send(res, 200, { ok: true });
    }

    if (path === '/api/credential' && req.method === 'POST') {
      const { raw } = JSON.parse(await readBody(req) || '{}');
      if (!raw) return send(res, 400, { ok: false, error: '内容为空' });
      const result = normalizeCredential(raw);
      if (!result.ok) return send(res, 400, result);
      saveJson(AUTH_PATH, { auth: result.auth });
      await restartBridge();
      return send(res, 200, { ok: true, account: result.account, endpoint: result.endpoint });
    }

    if (path === '/api/atrest-key' && req.method === 'POST') {
      const { key } = JSON.parse(await readBody(req) || '{}');
      const k = String(key || '').trim();
      if (!k) return send(res, 400, { ok: false, error: '密钥为空' });
      // 只做形状校验：真正的检验是能否解开一个信封，那要等用户上传 .info
      const buf = Buffer.from(k, 'base64');
      if (buf.length !== 32) {
        return send(res, 400, { ok: false, error: '密钥长度不对：应为 44 字符的 Base64（32 字节）' });
      }
      config.atrestKey = k;
      saveJson(CONFIG_PATH, config);
      return send(res, 200, { ok: true });
    }

    if (path === '/api/concurrency' && req.method === 'POST') {
      const { maxConcurrency } = JSON.parse(await readBody(req) || '{}');
      const n = Number(maxConcurrency);
      if (!Number.isInteger(n) || n < 0 || n > 16) {
        return send(res, 400, { ok: false, error: '并发需为 0~16 的整数' });
      }
      config.maxConcurrency = n;
      saveJson(CONFIG_PATH, config);
      // 并发是桥的启动参数，改完必须重启桥才生效
      await restartBridge();
      return send(res, 200, { ok: true, maxConcurrency: n });
    }

    if (path === '/api/password' && req.method === 'POST') {
      const { password } = JSON.parse(await readBody(req) || '{}');
      const p = String(password || '');
      if (p.length < 4) return send(res, 400, { ok: false, error: '口令至少 4 位' });
      config.consolePassword = p;
      saveJson(CONFIG_PATH, config);
      return send(res, 200, { ok: true }, {
        'Set-Cookie': `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`,
      });
    }

    if (path === '/api/keys' && req.method === 'POST') {
      const { label } = JSON.parse(await readBody(req) || '{}');
      const key = 'wb-' + randomBytes(18).toString('base64url');
      const id = randomBytes(6).toString('hex');
      config.clientKeys.push({
        id,
        key,
        label: String(label || '').slice(0, 40) || '未命名',
        createdAt: Date.now(),
      });
      saveJson(CONFIG_PATH, config);
      await restartBridge();
      return send(res, 200, { ok: true, id, key });
    }

    const delMatch = path.match(/^\/api\/keys\/([^/]+)$/);
    if (delMatch && req.method === 'DELETE') {
      const id = decodeURIComponent(delMatch[1]);
      const before = config.clientKeys.length;
      config.clientKeys = config.clientKeys.filter((k) => k.id !== id);
      if (config.clientKeys.length === before) {
        return send(res, 404, { ok: false, error: '没有这把 key' });
      }
      saveJson(CONFIG_PATH, config);
      await restartBridge();
      return send(res, 200, { ok: true });
    }

    return send(res, 404, { ok: false, error: 'not found' });
  } catch (e) {
    pushBridgeLog(`[console] ${req.method} ${path} 出错: ${e.message}`);
    return send(res, 500, { ok: false, error: e.message });
  }
});

/* 桥的请求工具已从 node:http 顶部导入（request as requestImpl） */

startBridge();

server.listen(PORT, HOST, () => {
  console.log(`[console] 控制台已启动：http://${HOST}:${PORT}`);
  console.log(`[console] 数据目录：${DATA}`);
  if (!config.consolePassword) {
    console.log('[console] 首次启动，管理口令见上面的日志');
  }
});

/*
 * 端口被占用必须**大声失败**。
 *
 * 原先没有 error 处理：`EADDRINUSE` 会作为未捕获异常打死整个进程，
 * 而 Docker 的 restart 策略会反复重启它 —— 用户看到的是「容器一直
 * healthy 不起来 / 日志空转」，完全猜不到是端口冲突。
 * 实测踩过：测试控制台与一个已有服务同端口时静默退出，排查了很久。
 */
server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`[console] ✗ 端口 ${PORT} 已被占用。`);
    console.error('  改 CONSOLE_PORT / AIGW_CONSOLE_PORT，或停掉占用该端口的程序。');
  } else if (err.code === 'EACCES') {
    console.error(`[console] ✗ 无权绑定端口 ${PORT}（1024 以下需要特权）。换个高位端口。`);
  } else {
    console.error(`[console] ✗ 控制台启动失败：${err.message}`);
  }
  process.exit(1);
});

const shutdown = async (signal) => {
  console.log(`[console] 收到 ${signal}，正在退出…`);
  stopping = true;
  await stopBridge();
  process.exit(0);
};
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
