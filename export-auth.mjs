#!/usr/bin/env node
/**
 * 把 WorkBuddy 桌面端的「加密登录文件」导出成**明文** auth JSON。
 *
 * 为什么需要：工作台的本地桥在 Windows 上能靠 WorkBuddy 的 Electron 二进制
 * 取到 atRestSecretKey 来解 AtRest 信封；NAS 的 Linux 容器里没有那个二进制，
 * 所以必须先在能跑客户端的那台机器上把令牌解出来，再带进容器。
 *
 * 桥本身对明文是**原生支持**的：openAuthField() 遇到字符串直接返回，
 * 不会调用 atRestKey()。因此导出的文件可以直接当 WORKBUDDY_AUTH_FILE 用。
 *
 * 用法（在装了 WorkBuddy 桌面端的机器上跑）：
 *   node export-auth.mjs --auth-file <登录文件> --out <输出文件>
 *
 * 例：
 *   node export-auth.mjs \
 *     --auth-file "C:\Users\me\AppData\Local\CodeBuddyExtension\Data\Public\auth\workbuddy-desktop.info" \
 *     --out ".\data\intl\workbuddy-auth.json"
 *
 * 安全性：输出文件里是**可直接使用的 bearer 令牌**，等同于账号密码。
 * 只放到 NAS 上权限收紧的目录，不要提交进 git、不要贴到聊天里。
 */

import { readFileSync, writeFileSync, existsSync, chmodSync } from 'node:fs';
import { createDecipheriv, createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { homedir } from 'node:os';

/* ── 参数 ─────────────────────────────────────────────────────────────── */

function arg(name) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

const PRINT_KEY = process.argv.includes('--print-key');

const AUTH_IN = arg('auth-file')
  || process.env.WORKBUDDY_AUTH_FILE
  || join(process.env.LOCALAPPDATA || '', 'CodeBuddyExtension', 'Data', 'Public', 'auth', 'workbuddy-desktop.info');
const OUT = arg('out') || 'workbuddy-auth.json';

/* ── `--print-key`：只输出 AtRest 密钥，供网页控制台「设置」里填 ──────
 *
 * 网页控制台要解密用户上传的 .info，需要这把密钥。它由客户端二进制里的
 * atRestSecretKey 经 SHA-256 派生，**同一台机器上稳定不变**，所以取一次即可。
 * 只打印这一项，不读登录文件 —— 没登录也能先拿到它。
 */
if (PRINT_KEY) {
  const got = atRestKey();
  console.log(Buffer.from(got.key).toString('base64'));
  console.error(`· 来源：${got.exe}`);
  console.error('· 把这串填进控制台「设置 → AtRest 密钥」');
  process.exit(0);
}

if (!existsSync(AUTH_IN)) {
  console.error(`✗ 登录文件不存在：${AUTH_IN}`);
  console.error('  用 --auth-file 指定，或先在 WorkBuddy 桌面端登录。');
  process.exit(1);
}

/* ── AtRest 解密（与桥内部实现等价）──────────────────────────────────── */

const ATREST_AAD_DOMAIN = Buffer.from('WB-AAD\0', 'ascii');

const encodeLengthPrefixed = (value) => {
  const bytes = Buffer.from(value, 'utf8');
  const len = Buffer.allocUnsafe(4);
  len.writeUInt32BE(bytes.length);
  return Buffer.concat([len, bytes]);
};

const atRestFieldAad = (keyId, suite) => {
  const suiteBytes = Buffer.allocUnsafe(4);
  suiteBytes.writeUInt32BE(suite);
  return Buffer.concat([
    ATREST_AAD_DOMAIN,
    Buffer.from([1]),
    encodeLengthPrefixed('WBEV1'),
    encodeLengthPrefixed('sym-v1'),
    suiteBytes,
    encodeLengthPrefixed(keyId),
    Buffer.from([2]),
    Buffer.from([0]),
    Buffer.from([0]),
  ]);
};

const atRestKeyId = (key) => createHash('sha256').update(key).digest('hex').slice(0, 16);

function isEncryptedField(value) {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const keys = Object.keys(value).sort();
  return keys.length === 2 && keys[0] === '$wbEncrypted' && keys[1] === 'envelope'
    && value.$wbEncrypted === 1 && typeof value.envelope === 'string';
}

/** 从 WorkBuddy 二进制取 atRestSecretKey，再按 keyId 选出能解信封的那把。 */
function atRestKey() {
  const exe = process.env.WORKBUDDY_APP_EXECUTABLE || process.env.WORKBUDDY_EXE;
  const candidates = [
    exe,
    process.platform === 'win32' && process.env.LOCALAPPDATA && join(process.env.LOCALAPPDATA, 'Programs', 'WorkBuddy', 'WorkBuddy.exe'),
    process.platform === 'win32' && process.env.LOCALAPPDATA && join(process.env.LOCALAPPDATA, 'Programs', 'WorkBuddyAI', 'WorkBuddyAI.exe'),
    process.platform === 'win32' && 'C:\\Users\\' + process.env.USERNAME + '\\AppData\\Local\\Programs\\WorkBuddyAI\\WorkBuddyAI.exe',
  ].filter(Boolean).filter((p) => existsSync(p));

  if (candidates.length === 0) {
    throw new Error('找不到 WorkBuddy 可执行文件；用 WORKBUDDY_APP_EXECUTABLE 指定');
  }

  const script =
    "try{process.stdout.write(process._linkedBinding('electron_browser_workbuddy_storage').loggerGet())}"
    + 'catch(e){process.exitCode=3;process.stderr.write(String((e&&e.message)||e))}';

  const failures = [];
  for (const bin of candidates) {
    const res = spawnSync(bin, ['-e', script], {
      env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' },
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 20000,
      windowsHide: true,
      maxBuffer: 1048576,
      encoding: 'utf8',
    });
    if (res.error || res.status !== 0) {
      failures.push(`${bin}: ${res.error?.message || `exit ${res.status}`}`);
      continue;
    }
    try {
      const secret = JSON.parse(res.stdout).atRestSecretKey;
      if (typeof secret !== 'string' || secret === '') continue;
      // 客户端哈希的是 base64 字符串本身，不是解码后的字节
      return { key: createHash('sha256').update(secret, 'utf8').digest(), exe: bin };
    } catch (e) {
      failures.push(`${bin}: ${e.message}`);
    }
  }
  throw new Error(`取密钥失败：${failures.join(' | ')}`);
}

function openField(value, label, key) {
  if (typeof value === 'string') return value; // 已是明文
  if (!isEncryptedField(value)) return '';
  const envelope = JSON.parse(Buffer.from(value.envelope, 'base64').toString('utf8'));
  const expected = atRestKeyId(key);
  if (envelope.keyId !== expected) {
    throw new Error(`${label} 的信封 keyId=${envelope.keyId}，与当前客户端的 ${expected} 不符`);
  }
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.nonce, 'base64'), { authTagLength: 16 });
  decipher.setAAD(atRestFieldAad(envelope.keyId, envelope.suite));
  decipher.setAuthTag(Buffer.from(envelope.authTag, 'base64'));
  return Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, 'base64')),
    decipher.final(),
  ]).toString('utf8');
}

/* ── 导出 ─────────────────────────────────────────────────────────────── */

const raw = JSON.parse(readFileSync(AUTH_IN, 'utf8'));
const auth = raw.auth || {};

if (!auth.accessToken) {
  console.error('✗ 登录文件里没有 accessToken；先在 WorkBuddy 桌面端登录');
  process.exit(1);
}

// 明文就跳过取密钥（容器里没二进制时也能重跑本脚本做无损转换）
const needsKey = isEncryptedField(auth.accessToken);
let key = null;
if (needsKey) {
  const got = atRestKey();
  key = got.key;
  console.error(`· 用 ${got.exe} 取到密钥`);
} else {
  console.error('· 登录文件已是明文，无需取密钥');
}

const access = openField(auth.accessToken, 'accessToken', key);
const refresh = openField(auth.refreshToken, 'refreshToken', key);

if (!access) {
  console.error('✗ 解不出 accessToken');
  process.exit(1);
}

/* 只保留桥真正会读的字段，并把令牌降级成明文字符串。 */
const out = {
  _note: '明文凭据，等同账号密码。权限收紧、勿提交、勿外传。由 export-auth.mjs 生成。',
  auth: {
    accessToken: access,
    refreshToken: refresh,
    domain: auth.domain || '',
    expiresAt: Number(auth.expiresAt || 0),
    refreshExpiresAt: Number(auth.refreshExpiresAt || 0),
  },
};

writeFileSync(OUT, JSON.stringify(out, null, 2), 'utf8');
try { chmodSync(OUT, 0o600); } catch { /* Windows 上可能不支持，忽略 */ }

/* 只回显「是谁、哪个网关、什么时候到期」，绝不回显令牌本身。 */
const claims = (() => {
  try { return JSON.parse(Buffer.from(access.split('.')[1], 'base64url').toString('utf8')); } catch { return {}; }
})();

console.log(`✓ 已导出 ${OUT}`);
console.log(`  账号   : ${claims.sub || '(无 sub)'}`);
console.log(`  域名   : ${auth.domain || '(未记录)'}`);
console.log(`  到期   : ${out.auth.expiresAt ? new Date(out.auth.expiresAt).toISOString() : '(未知)'}`);
console.log('');
console.log('把该文件放到 NAS 上对应账号的目录，容器里用 WORKBUDDY_AUTH_FILE 指向它。');
