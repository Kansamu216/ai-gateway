/**
 * 手工解析 Electron asar：列出条目 / 提取单个文件的文本。
 * 之所以手写，是因为 Electron 的 asar 支持会拦截 fs，而我们需要同时
 * 「读原始字节」与「按路径读内部文件」两种能力。
 */
process.noAsar = true;

const fs = require('fs');

const ASAR = process.argv[2];
const MODE = process.argv[3];     // 'list' | 'grep'
const PATTERN = process.argv[4];  // grep 用的正则
const ONLY = process.argv[5];     // 只搜文件名含该子串的文件

const fd = fs.openSync(ASAR, 'r');
const head = Buffer.alloc(16);
fs.readSync(fd, head, 0, 16, 0);
const headerSize = head.readUInt32LE(12);
const hb = Buffer.alloc(headerSize);
fs.readSync(fd, hb, 0, headerSize, 16);
const manifest = JSON.parse(hb.toString('utf8').replace(/\0+$/u, ''));

/* asar 的 data 区从 header 之后开始；文件 offset 相对它 */
const DATA_START = 16 + headerSize;

const entries = [];
(function walk(node, prefix) {
  for (const [name, v] of Object.entries(node.files || {})) {
    const p = prefix + '/' + name;
    if (v.files) walk(v, p);
    /*
     * 注意：新版 Electron 把 offset 序列化成**字符串**（"0"，不是 0）。
     * 早先这里判断 `typeof v.offset === 'number'`，于是整棵树的文件一个都
     * 没进 entries —— 表现为 "0 entries"，而不是报错，极难发现。
     */
    else if (v.offset !== undefined) {
      entries.push({ path: p, offset: Number(v.offset), size: Number(v.size || 0) });
    }
  }
})(manifest, '');

if (MODE === 'list') {
  for (const e of entries) console.log(e.size.toString().padStart(9), e.path);
  console.log('---', entries.length, 'entries ---');
  process.exit(0);
}

const re = new RegExp(PATTERN, 'gi');
let hits = 0;
for (const e of entries) {
  if (ONLY && !e.path.includes(ONLY)) continue;
  if (e.size > 12 * 1024 * 1024) continue; // 超大文件跳过
  const buf = Buffer.alloc(e.size);
  fs.readSync(fd, buf, 0, e.size, DATA_START + e.offset);
  const text = buf.toString('utf8');
  const seen = new Set();
  for (const m of text.matchAll(re)) {
    const s = m[0].slice(0, 160).replace(/\s+/g, ' ');
    if (seen.has(s)) continue;
    seen.add(s);
    if (hits++ < 80) console.log(e.path + '  ::  ' + s);
  }
}
console.log('--- hits:', hits, '---');
fs.closeSync(fd);
