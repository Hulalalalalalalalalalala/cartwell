import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import net from 'node:net';

// 回归测试：通过真实的 HTTP 请求、响应和保存后的商品列表观察新增商品行为，
// 重点保证同一商品内重复规格的判定不随属性填写顺序变化。

const SERVER_PATH = join(import.meta.dirname, 'server.ts');

interface RunningServer {
  url: string;
  dataDir: string;
  child: ChildProcess;
}

function startServer(): Promise<RunningServer> {
  const dataDir = mkdtempSync(join(tmpdir(), 'cartwell-test-'));
  const child = spawn(
    process.execPath,
    [SERVER_PATH, 'serve', '--host', '127.0.0.1', '--port', '0', '--data-dir', dataDir],
    { stdio: ['ignore', 'pipe', 'pipe'] },
  );
  return new Promise((resolve, reject) => {
    let buffer = '';
    let settled = false;
    const fail = (error: Error): void => {
      if (!settled) { settled = true; reject(error); }
    };
    child.stdout!.setEncoding('utf8');
    child.stdout!.on('data', (chunk: string) => {
      buffer += chunk;
      const match = buffer.match(/listening on (http:\/\/\S+)/);
      if (match && !settled) {
        settled = true;
        resolve({ url: match[1], dataDir, child });
      }
    });
    child.stderr!.setEncoding('utf8');
    child.stderr!.on('data', (chunk: string) => { buffer += chunk; });
    child.once('error', () => fail(new Error('无法启动服务进程')));
    child.once('exit', (code) => fail(new Error(`服务提前退出，退出码 ${code}：${buffer}`)));
  });
}

async function stopServer(server: RunningServer): Promise<void> {
  server.child.kill('SIGTERM');
  await Promise.race([
    once(server.child, 'exit'),
    new Promise((resolve) => setTimeout(resolve, 5000)),
  ]);
  if (server.child.exitCode === null) server.child.kill('SIGKILL');
  rmSync(server.dataDir, { recursive: true, force: true });
}

interface ApiResult {
  status: number;
  body: any;
}

async function postProduct(url: string, payload: unknown): Promise<ApiResult> {
  const response = await fetch(`${url}/api/products`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  });
  return { status: response.status, body: await response.json() };
}

async function getProducts(url: string): Promise<any[]> {
  const response = await fetch(`${url}/api/products`);
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.ok(Array.isArray(body.products));
  return body.products;
}

const MAX_BODY_BYTES = 1_048_576;

interface RawResponse {
  statusLine: string;
  statusCode: number;
  headers: string;
  body: Buffer;
  hadError: boolean;
}

// 直接用 TCP 发送原始 HTTP 请求，便于精确控制 Content-Length、分块边界和发送节奏，
// 同时观察连接是否被重置以及响应是否完整（fetch 无法区分「连接断开」与「400 响应」）。
function rawRequest(url: string, headExtra: string, chunks: Buffer[]): Promise<RawResponse> {
  const { port } = new URL(url);
  return new Promise((resolve, reject) => {
    const client = net.connect(Number(port), '127.0.0.1');
    const received: Buffer[] = [];
    client.on('connect', () => {
      client.write(`POST /api/products HTTP/1.1\r\nHost: localhost\r\n${headExtra}\r\n\r\n`);
      let index = 0;
      const sendNext = (): void => {
        if (index >= chunks.length) { client.end(); return; }
        client.write(chunks[index++]);
        setImmediate(sendNext);
      };
      sendNext();
    });
    client.on('data', (chunk) => received.push(chunk));
    client.on('error', (error) => reject(error));
    client.on('close', (hadError) => {
      const raw = Buffer.concat(received);
      const split = raw.indexOf('\r\n\r\n');
      const head = split >= 0 ? raw.subarray(0, split).toString('utf8') : '';
      const statusLine = head.split('\r\n')[0] ?? '';
      const statusCode = Number(statusLine.slice(9, 12)) || 0;
      let body = split >= 0 ? raw.subarray(split + 4) : Buffer.alloc(0);
      if (/transfer-encoding:\s*chunked/i.test(head)) body = dechunk(body);
      resolve({ statusLine, statusCode, headers: head, body, hadError });
    });
  });
}

function dechunk(payload: Buffer): Buffer {
  const out: Buffer[] = [];
  let rest = payload;
  for (;;) {
    const lineEnd = rest.indexOf('\r\n');
    if (lineEnd < 0) break;
    const length = parseInt(rest.subarray(0, lineEnd).toString('ascii'), 16);
    if (!Number.isFinite(length) || length <= 0) break;
    out.push(rest.subarray(lineEnd + 2, lineEnd + 2 + length));
    rest = rest.subarray(lineEnd + 2 + length + 2);
  }
  return Buffer.concat(out);
}

async function postRawWithLength(url: string, body: Buffer, chunks?: Buffer[]): Promise<RawResponse> {
  return rawRequest(url, `Content-Type: application/json\r\nContent-Length: ${body.length}`, chunks ?? [body]);
}

async function postRawChunked(url: string, body: Buffer, segmented = false): Promise<RawResponse> {
  // 把实际内容按每 100_000 字节编码成 chunked 数据帧
  const frames: string[] = [];
  for (let offset = 0; offset < body.length; offset += 100_000) {
    const piece = body.subarray(offset, Math.min(offset + 100_000, body.length));
    frames.push(`${piece.length.toString(16)}\r\n${piece.toString('latin1')}\r\n`);
  }
  frames.push('0\r\n\r\n');
  const wire = Buffer.from(frames.join(''), 'latin1');
  if (!segmented) return rawRequest(url, 'Content-Type: application/json\r\nTransfer-Encoding: chunked', [wire]);
  // 帧本身再按 300_000 字节边界拆成多次 TCP 写入（与 chunk 边界刻意不对齐）
  const sendChunks: Buffer[] = [];
  for (let offset = 0; offset < wire.length; offset += 300_000) {
    sendChunks.push(wire.subarray(offset, Math.min(offset + 300_000, wire.length)));
  }
  return rawRequest(url, 'Content-Type: application/json\r\nTransfer-Encoding: chunked', sendChunks);
}

// 断言超限响应完整、可解析，且原因明确是「超过大小限制」而不是字段校验或 JSON 错误。
function assertTooLargeResponse(result: RawResponse): any {
  assert.equal(result.statusCode, 400, `超限请求应返回 400，实际：${result.statusLine}`);
  assert.ok(!result.hadError, '连接不应被重置，客户端应收到完整响应');
  assert.match(result.headers, /content-length:\s*\d+/i, '响应应带正确的 content-length');
  assert.equal(
    result.body.length,
    Number(result.headers.match(/content-length:\s*(\d+)/i)![1]),
    '响应正文应与 content-length 一致，不能是半截响应',
  );
  let parsed: any;
  assert.doesNotThrow(() => { parsed = JSON.parse(result.body.toString('utf8')); }, '响应应是可解析的完整 JSON');
  assert.match(parsed.error, /请求体超过/, '错误说明应指出请求体超过大小限制');
  assert.match(parsed.error, /商品没有保存|未保存|没有保存/, '错误说明应明确商品没有保存');
  assert.equal(parsed.limitBytes, MAX_BODY_BYTES);
  return parsed;
}

function spec(attributes: Array<[string, string]>, price = '10.00', stock = 5) {
  return {
    attributes: attributes.map(([name, value]) => ({ name, value })),
    price,
    stock,
  };
}

function productPayload(name: string, specs: unknown[]) {
  return { name, specs };
}

test('合法请求返回 201 及完整商品记录，之后能从列表查到且最新创建的商品排在最前', async (t) => {
  const server = await startServer();
  t.after(() => stopServer(server));

  const first = await postProduct(server.url, productPayload('基础T恤', [
    spec([['颜色', '红色'], ['尺码', 'M']], '99', 20),
    spec([['颜色', '红色'], ['尺码', 'L']], '99.5', 0),
  ]));
  assert.equal(first.status, 201);
  assert.equal(typeof first.body.id, 'string');
  assert.notEqual(first.body.id, '');
  assert.equal(first.body.name, '基础T恤');
  assert.equal(typeof first.body.createdAt, 'string');
  assert.ok(!Number.isNaN(Date.parse(first.body.createdAt)));
  assert.equal(first.body.specs.length, 2);
  // 金额统一为两位小数字符串，库存原样保存
  assert.deepEqual(first.body.specs[0], {
    attributes: [{ name: '颜色', value: '红色' }, { name: '尺码', value: 'M' }],
    price: '99.00',
    stock: 20,
  });
  assert.deepEqual(first.body.specs[1], {
    attributes: [{ name: '颜色', value: '红色' }, { name: '尺码', value: 'L' }],
    price: '99.50',
    stock: 0,
  });

  const second = await postProduct(server.url, productPayload('帆布帽', [
    spec([['颜色', '卡其']], '45.00', 8),
  ]));
  assert.equal(second.status, 201);

  const products = await getProducts(server.url);
  assert.equal(products.length, 2);
  assert.equal(products[0].id, second.body.id, '最新创建的商品应排在最前');
  assert.equal(products[1].id, first.body.id);
  assert.deepEqual(products[1], first.body, '列表中的记录应与创建时返回的完整记录一致');
});

test('属性填写顺序不同、售价和库存也不同，仍判定为重复规格并返回 400', async (t) => {
  const server = await startServer();
  t.after(() => stopServer(server));

  const result = await postProduct(server.url, productPayload('基础T恤', [
    spec([['颜色', '红色'], ['尺码', 'M']], '99.00', 20),
    // 第二条先填写尺码，售价、库存与第一条不同，仍属于重复规格
    spec([['尺码', 'M'], ['颜色', '红色']], '79.50', 3),
  ]));

  assert.equal(result.status, 400);
  assert.equal(result.body.error, '商品校验未通过，未创建任何记录');
  assert.ok(Array.isArray(result.body.details));

  const specErrors = result.body.details.filter((detail: any) => detail.field === 'spec');
  assert.deepEqual(
    specErrors.map((detail: any) => detail.specIndex).sort(),
    [0, 1],
    '参与冲突的两条规格都应在 details 中指出位置',
  );
  for (const detail of specErrors) {
    assert.equal(typeof detail.message, 'string');
    assert.notEqual(detail.message, '');
  }
  assert.ok(
    specErrors.some((detail: any) => detail.path === 'specs[0]' && detail.message.includes('第 2 条')),
    '第 1 条规格的错误应说明它与第 2 条重复',
  );
  assert.ok(
    specErrors.some((detail: any) => detail.path === 'specs[1]' && detail.message.includes('第 1 条')),
    '第 2 条规格的错误应说明它与第 1 条重复',
  );

  assert.deepEqual(await getProducts(server.url), [], '被拒绝的商品不能留下记录');
});

test('属性文字带首尾空白不能绕过重复规格限制', async (t) => {
  const server = await startServer();
  t.after(() => stopServer(server));

  const result = await postProduct(server.url, productPayload('基础T恤', [
    spec([['颜色', '红色'], ['尺码', 'M']], '99.00', 20),
    spec([['  颜色  ', '红色  '], ['  尺码', '  M']], '99.00', 20),
  ]));

  assert.equal(result.status, 400);
  const specErrors = result.body.details.filter((detail: any) => detail.field === 'spec');
  assert.deepEqual(specErrors.map((detail: any) => detail.specIndex).sort(), [0, 1]);
  assert.deepEqual(await getProducts(server.url), [], '被拒绝的商品不能留下记录');
});

test('同一商品混合合法规格与重复规格时整个商品都不保存，已有商品保持原样', async (t) => {
  const server = await startServer();
  t.after(() => stopServer(server));

  const existing = await postProduct(server.url, productPayload('已有商品', [
    spec([['颜色', '黑色'], ['尺码', 'S']], '59.00', 12),
  ]));
  assert.equal(existing.status, 201);
  const before = await getProducts(server.url);
  assert.equal(before.length, 1);

  const rejected = await postProduct(server.url, productPayload('新商品', [
    spec([['颜色', '蓝色']], '30.00', 4), // 合法规格
    spec([['颜色', '红色'], ['尺码', 'M']], '99.00', 20),
    spec([['尺码', 'M'], ['颜色', '红色']], '88.00', 7), // 与上一条重复
  ]));
  assert.equal(rejected.status, 400);
  assert.ok(
    rejected.body.details.some((detail: any) => detail.field === 'spec' && detail.specIndex === 1)
    && rejected.body.details.some((detail: any) => detail.field === 'spec' && detail.specIndex === 2),
    'details 应指出参与冲突的规格位置',
  );

  const after = await getProducts(server.url);
  assert.deepEqual(after, before, '已有商品及其规格、售价和库存应保持原样');
  assert.ok(
    after.every((product) => product.name !== '新商品'),
    '不能只保存其中合法的部分，列表中不能出现被拒绝的商品',
  );
});

test('只要完整的属性名称和值组合不同就允许创建：部分属性相同或属性数量不同都不算重复', async (t) => {
  const server = await startServer();
  t.after(() => stopServer(server));

  const result = await postProduct(server.url, productPayload('基础T恤', [
    spec([['颜色', '红色'], ['尺码', 'M']], '99.00', 20),
    spec([['颜色', '红色'], ['尺码', 'L']], '99.00', 0), // 尺码不同
    spec([['颜色', '红色']], '89.00', 15), // 少一个属性，不能仅因颜色相同被当作重复
  ]));

  assert.equal(result.status, 201);
  assert.equal(result.body.specs.length, 3);
  const products = await getProducts(server.url);
  assert.equal(products.length, 1);
  assert.equal(products[0].id, result.body.id);
  assert.equal(products[0].specs.length, 3);
});

test('重复判定区分字母大小写：属性值和属性名称的大小写不同都是不同规格', async (t) => {
  const server = await startServer();
  t.after(() => stopServer(server));

  const values = await postProduct(server.url, productPayload('尺码商品', [
    spec([['尺码', 'M']], '10.00', 1),
    spec([['尺码', 'm']], '10.00', 1),
  ]));
  assert.equal(values.status, 201, '「M」与「m」应是不同值');

  const names = await postProduct(server.url, productPayload('颜色商品', [
    spec([['Color', '红色']], '10.00', 1),
    spec([['color', '红色']], '10.00', 1),
  ]));
  assert.equal(names.status, 201, '属性名称同样区分大小写');

  const products = await getProducts(server.url);
  assert.equal(products.length, 2);
});

test('重复限制只作用于同一次新增的商品：不同商品允许相同规格，商品名称相同也不扩大比较范围', async (t) => {
  const server = await startServer();
  t.after(() => stopServer(server));

  const sharedSpec = spec([['颜色', '红色'], ['尺码', 'M']], '99.00', 20);

  const first = await postProduct(server.url, productPayload('基础T恤', [sharedSpec]));
  assert.equal(first.status, 201);

  // 另一件商品使用与已有商品完全相同的规格
  const second = await postProduct(server.url, productPayload('同款T恤', [
    spec([['尺码', 'M'], ['颜色', '红色']], '99.00', 20),
  ]));
  assert.equal(second.status, 201, '已有商品使用过的规格不妨碍另一件商品使用');

  // 商品名称相同也不应扩大比较范围
  const third = await postProduct(server.url, productPayload('基础T恤', [sharedSpec]));
  assert.equal(third.status, 201, '商品名称相同不应把不同商品的规格放在一起比较');

  const products = await getProducts(server.url);
  assert.deepEqual(
    products.map((product) => product.id),
    [third.body.id, second.body.id, first.body.id],
    '三个商品都应保存，且最新创建的商品排在最前',
  );
});

// ---------- 请求体大小限制 ----------

// 构造在某个属性值里填充 n 个 ASCII 字符的商品 JSON；每多一个字符请求体恰好多一个字节。
function paddedProductJson(pad: number, price = '1.00'): Buffer {
  return Buffer.from(JSON.stringify({
    name: '边界商品',
    specs: [{ attributes: [{ name: '颜色', value: 'a'.repeat(pad) }], price, stock: 1 }],
  }), 'utf8');
}

// 找到请求体字节数不超过上限的最大填充长度（ASCII 填充时可恰好凑到上限）。
function maxPadWithinLimit(price = '1.00'): number {
  let lo = 0;
  let hi = MAX_BODY_BYTES;
  while (lo < hi) {
    const mid = Math.floor((lo + hi + 1) / 2);
    if (paddedProductJson(mid, price).length <= MAX_BODY_BYTES) lo = mid;
    else hi = mid - 1;
  }
  return lo;
}

test('请求体超过上限（一次性发送）时返回完整可解析的 400 JSON，而不是重置连接', async (t) => {
  const server = await startServer();
  t.after(() => stopServer(server));

  const result = await postRawWithLength(server.url, Buffer.alloc(MAX_BODY_BYTES + 1, 0x78));
  assertTooLargeResponse(result);
  assert.deepEqual(await getProducts(server.url), [], '超限请求不能创建商品或部分规格');
});

test('同一份超限内容：整体发送、分多段发送、chunked 分段传输得到一致的超限 400', async (t) => {
  const server = await startServer();
  t.after(() => stopServer(server));

  const body = paddedProductJson(maxPadWithinLimit() + 1);
  assert.ok(body.length > MAX_BODY_BYTES);

  // 预先声明长度并一次性发送
  const bulk = await postRawWithLength(server.url, body);
  // 预先声明相同长度，但把请求体切成多段发送
  const segments: Buffer[] = [];
  for (let offset = 0; offset < body.length; offset += 200_000) {
    segments.push(body.subarray(offset, Math.min(offset + 200_000, body.length)));
  }
  assert.ok(segments.length > 1, '测试前提：内容确实被分成多段');
  const split = await postRawWithLength(server.url, body, segments);
  // 使用 Transfer-Encoding: chunked，帧本身也分多次写入（写入边界与 chunk 边界不对齐）
  const one = await postRawChunked(server.url, body, true);
  // chunked 数据一次性写入
  const chunkedBulk = await postRawChunked(server.url, body);

  for (const result of [bulk, split, one, chunkedBulk]) {
    assertTooLargeResponse(result);
  }
  assert.ok(
    bulk.body.equals(split.body) && bulk.body.equals(one.body) && bulk.body.equals(chunkedBulk.body),
    '不同发送方式应返回完全一致的响应',
  );
  assert.deepEqual(await getProducts(server.url), []);
});

test('恰好达到上限的合法请求进入原有校验并创建成功，只多一个字节才按超限拒绝', async (t) => {
  const server = await startServer();
  t.after(() => stopServer(server));

  const pad = maxPadWithinLimit();
  const exact = paddedProductJson(pad);
  assert.equal(exact.length, MAX_BODY_BYTES, '测试前提：请求体恰好等于上限');
  const exactResult = await postRawWithLength(server.url, exact);
  assert.equal(exactResult.statusCode, 201, '恰好达到上限的合法请求应创建成功');
  assert.match(exactResult.body.toString('utf8'), /"id"/);

  const over = paddedProductJson(pad + 1);
  assert.equal(over.length, MAX_BODY_BYTES + 1);
  assertTooLargeResponse(await postRawWithLength(server.url, over));
});

test('恰好达到上限但内容不是合法 JSON 时仍按 JSON 错误拒绝，只有超过上限才算请求过大', async (t) => {
  const server = await startServer();
  t.after(() => stopServer(server));

  // 未闭合的对象（前缀后全部填 JSON 空白），恰好 1 MiB，解析必然失败但与大小无关
  const invalid = Buffer.concat([
    Buffer.from('{"x":'),
    Buffer.alloc(MAX_BODY_BYTES - 5, 0x20),
  ]);
  assert.equal(invalid.length, MAX_BODY_BYTES);
  const result = await postRawWithLength(server.url, invalid);
  assert.equal(result.statusCode, 400);
  const parsed = JSON.parse(result.body.toString('utf8'));
  assert.equal(parsed.error, '请求内容不是合法的 JSON', '恰好上限不应被误报为超限');
});

test('超过上限时即使同时是非法 JSON，也只报超限原因', async (t) => {
  const server = await startServer();
  t.after(() => stopServer(server));

  const invalid = Buffer.from(`{ not json ${'z'.repeat(MAX_BODY_BYTES)}}`);
  assert.ok(invalid.length > MAX_BODY_BYTES);
  assertTooLargeResponse(await postRawWithLength(server.url, invalid));
  assert.deepEqual(await getProducts(server.url), []);
});

test('超过上限时即使同时包含非法售价等字段问题，也只报超限而不是字段不合规', async (t) => {
  const server = await startServer();
  t.after(() => stopServer(server));

  const pad = maxPadWithinLimit('-99');
  const body = paddedProductJson(pad + 1, '-99');
  assert.ok(body.length > MAX_BODY_BYTES);
  const parsed = assertTooLargeResponse(await postRawWithLength(server.url, body));
  assert.equal(parsed.details, undefined, '不能把超限请求误报成商品字段不合规');
  assert.deepEqual(await getProducts(server.url), []);
});

test('大小限制按 UTF-8 字节计算：字符数未超限但字节数超限的中文属性同样拒绝', async (t) => {
  const server = await startServer();
  t.after(() => stopServer(server));

  // 每个「红」字占 3 个字节：约 35 万个字符就超过 1 MiB，字符数远小于字节上限。
  const body = Buffer.from(JSON.stringify({
    name: '中文商品',
    specs: [{ attributes: [{ name: '颜色', value: '红'.repeat(400_000) }], price: '1.00', stock: 1 }],
  }), 'utf8');
  assert.ok(body.length < 3 * 400_000 + 1000 && body.length > MAX_BODY_BYTES);
  assertTooLargeResponse(await postRawWithLength(server.url, body));
  assert.deepEqual(await getProducts(server.url), []);
});

test('处理超限请求后已有商品、售价和库存保持原样，且仍能正常新增另一件合法商品', async (t) => {
  const server = await startServer();
  t.after(() => stopServer(server));

  const existing = await postProduct(server.url, productPayload('已有商品', [
    spec([['颜色', '黑色'], ['尺码', 'S']], '59.00', 12),
    spec([['颜色', '黑色'], ['尺码', 'M']], '69.5', 0),
  ]));
  assert.equal(existing.status, 201);
  const before = await getProducts(server.url);

  // 连续两次超限（一次 chunked、一次声明长度），其中一次还夹带非法售价
  assertTooLargeResponse(await postRawChunked(server.url, Buffer.alloc(MAX_BODY_BYTES + 10, 0x71)));
  const pad = maxPadWithinLimit('-1');
  assertTooLargeResponse(await postRawWithLength(server.url, paddedProductJson(pad + 1, '-1')));

  const after = await getProducts(server.url);
  assert.deepEqual(after, before, '此前保存的商品、售价和库存保持原样');
  assert.ok(
    after.every((product) => product.name === '已有商品'),
    '超限商品不能出现在列表中，也不能留下部分规格',
  );

  // 服务仍可正常查询与新增
  const another = await postProduct(server.url, productPayload('另一件合法商品', [
    spec([['颜色', '白色']], '39.90', 3),
  ]));
  assert.equal(another.status, 201);
  assert.equal(another.body.specs[0].price, '39.90', '金额仍以两位小数字符串展示');
  const finalList = await getProducts(server.url);
  assert.equal(finalList.length, 2);
  assert.equal(finalList[0].id, another.body.id, '新商品排在列表最前');
  assert.deepEqual(finalList[1], before[0], '此前的商品记录完整保留');
});

// ---------- 售价校验与金额规范化回归 ----------

// 构造仅含一个「款式」属性的规格，便于单独替换售价观察校验行为。
function priceSpec(value: string, price: unknown, stock = 3) {
  return { attributes: [{ name: '款式', value }], price, stock };
}

// 按属性值找到对应规格，验证金额规范化后仍与原属性组合绑定，没有互换或覆盖。
function specByAttr(product: any, value: string): any {
  const found = product.specs.find((item: any) => item.attributes[0].value === value);
  assert.ok(found, `应存在款式为「${value}」的规格`);
  return found;
}

test('合法售价统一规范化为两位小数字符串：零、整数、一位/两位小数和前导零都按规则转换', async (t) => {
  const server = await startServer();
  t.after(() => stopServer(server));

  const result = await postProduct(server.url, productPayload('金额规范化商品', [
    priceSpec('零款', '0', 0),
    priceSpec('整数款', '12', 1),
    priceSpec('一位小数款', '12.5', 2),
    priceSpec('两位小数款', '12.50', 3),
    priceSpec('前导零款', '00012.30', 4),
  ]));

  assert.equal(result.status, 201);
  const created = result.body;
  const cases: Array<[string, string, number]> = [
    ['零款', '0.00', 0],
    ['整数款', '12.00', 1],
    ['一位小数款', '12.50', 2],
    ['两位小数款', '12.50', 3], // 已有两位小数不被改写
    ['前导零款', '12.30', 4], // 前导零去掉，不能得到 012.30
  ];
  for (const [value, expectedPrice, expectedStock] of cases) {
    const item = specByAttr(created, value);
    assert.equal(typeof item.price, 'string', `「${value}」售价必须仍是字符串`);
    assert.equal(item.price, expectedPrice, `「${value}」的 ${String(item.price)} 应规范化为 ${expectedPrice}`);
    assert.equal(item.stock, expectedStock, `「${value}」的金额应与原属性组合、库存对应，不能互换`);
  }

  const products = await getProducts(server.url);
  assert.equal(products.length, 1);
  assert.deepEqual(products[0], created, '列表记录应与创建响应完全一致');
});

test('超出 JavaScript 安全整数范围的两位小数售价在响应原文和列表中都完整保留，不丢位、不变指数', async (t) => {
  const server = await startServer();
  t.after(() => stopServer(server));

  const bigPrice = '9007199254740993.01';
  assert.notEqual(
    String(Number(bigPrice)), bigPrice,
    '测试前提：该金额整数部分超过安全整数范围，若按数字处理必然丢位',
  );

  // 直接读取响应文本：即便将来售价被误写成 JSON 数字，在线路上也会表现为丢位或指数形式。
  const response = await fetch(`${server.url}/api/products`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(productPayload('超大金额商品', [
      priceSpec('超大款', bigPrice, 7),
      priceSpec('普通款', '1.01', 2),
    ])),
  });
  const text = await response.text();
  assert.equal(response.status, 201);
  assert.match(
    text, new RegExp(`"price":"${bigPrice.replace(/\./g, '\\.')}"`),
    '创建响应原文中的售价必须逐位保留为字符串，不能丢位或变成指数形式',
  );
  const created = JSON.parse(text);

  const bigSpec = specByAttr(created, '超大款');
  assert.equal(typeof bigSpec.price, 'string');
  assert.equal(bigSpec.price, bigPrice, '全部 16 位整数和两位小数都必须保留');
  assert.doesNotMatch(bigSpec.price, /e|E/, '不能出现指数形式');
  assert.match(bigSpec.price, /^\d+\.\d{2}$/, '只能有恰好两位小数，不能出现多余小数');
  assert.equal(specByAttr(created, '普通款').price, '1.01', '另一规格的金额不能受大金额规格影响');

  const products = await getProducts(server.url);
  assert.deepEqual(products[0], created, '随后查询到的规格必须与创建结果一致');
  assert.equal(specByAttr(products[0], '超大款').price, bigPrice, '列表查询同样必须保留全部数字');
});

test('其他字段均合规时，各类不合规售价返回 400 且 details 明确指出规格与售价字段，商品不保存', async (t) => {
  const server = await startServer();
  t.after(() => stopServer(server));

  const badPrices: Array<[string, unknown]> = [
    ['负数', '-1'],
    ['负的小数金额', '-0.01'],
    ['指数写法（小写 e）', '1e3'],
    ['指数写法（大写 E）', '1.5E2'],
    ['千位分隔符', '1,000.00'],
    ['超过两位小数', '12.345'],
    ['更多位小数', '12.3456'],
    ['售价作为 JSON 整数数字提交', 12],
    ['售价作为 JSON 小数数字提交', 12.5],
    ['空字符串', ''],
    ['空值 null', null],
  ];

  for (const [label, price] of badPrices) {
    const result = await postProduct(server.url, productPayload(`非法售价-${label}`, [
      priceSpec('唯一款', price, 5),
    ]));
    assert.equal(result.status, 400, `售价「${String(price)}」（${label}）应被拒绝`);

    const priceErrors = result.body.details.filter((detail: any) => detail.field === 'price');
    assert.equal(priceErrors.length, 1, `「${label}」应只有一条售价错误`);
    assert.equal(priceErrors[0].specIndex, 0, `「${label}」的错误应指出第 1 条规格`);
    assert.equal(priceErrors[0].path, 'specs[0].price', `「${label}」的错误路径应指向售价字段`);
    assert.match(priceErrors[0].message, /售价/, `「${label}」的错误说明应明确是售价问题`);
    assert.ok(
      result.body.details.every((detail: any) => detail.field === 'price'),
      `名称、属性、库存均合规时，「${label}」不应产生售价以外的错误`,
    );

    assert.deepEqual(await getProducts(server.url), [], `「${label}」被拒绝后不能留下商品记录`);
  }
});

test('12.345 等超过两位小数的售价不会被四舍五入、截断或套用默认值保存', async (t) => {
  const server = await startServer();
  t.after(() => stopServer(server));

  for (const raw of ['12.345', '12.349', '0.000']) {
    const result = await postProduct(server.url, productPayload('多余小数商品', [
      priceSpec('唯一款', raw, 5),
    ]));
    assert.equal(result.status, 400, `售价「${raw}」必须拒绝，而不是规整后保存`);
    assert.ok(
      result.body.details.some((detail: any) => detail.field === 'price' && detail.specIndex === 0),
      '拒绝原因必须明确是该规格的售价字段',
    );
  }

  const products = await getProducts(server.url);
  assert.deepEqual(products, [], '不能出现 12.35、12.34 或任何默认金额的记录');
  assert.ok(
    !JSON.stringify(products).includes('12.3'),
    '任何多余小数售价都不能换一种形式进入列表',
  );
});

test('多条规格售价同时不合规时，details 分别指出各自位置以便逐个修正', async (t) => {
  const server = await startServer();
  t.after(() => stopServer(server));

  const result = await postProduct(server.url, productPayload('多条售价问题商品', [
    priceSpec('合法一', '10.00', 1),
    priceSpec('非法一', '12.345', 2), // 超过两位小数
    priceSpec('非法二', '-5', 3), // 负数
    priceSpec('合法二', '8.8', 4),
    priceSpec('非法三', 999, 5), // JSON 数字
  ]));

  assert.equal(result.status, 400);
  const priceErrors = result.body.details.filter((detail: any) => detail.field === 'price');
  assert.deepEqual(
    priceErrors.map((detail: any) => detail.specIndex).sort((a: number, b: number) => a - b),
    [1, 2, 4],
    '三条非法售价规格的位置都应被指出',
  );
  for (const specIndex of [1, 2, 4]) {
    assert.ok(
      priceErrors.some((detail: any) => detail.specIndex === specIndex && detail.path === `specs[${specIndex}].price`),
      `第 ${specIndex + 1} 条规格的售价字段应被单独指出`,
    );
  }
  assert.ok(
    ![0, 3].some((index) => priceErrors.some((detail: any) => detail.specIndex === index)),
    '售价合法的规格不应出现在售价错误中',
  );

  assert.deepEqual(await getProducts(server.url), [], '被拒绝的商品不能留下记录');
});

test('一件商品混有合法与非法售价规格时整个商品都不创建，已有商品的完整记录、售价和库存保持原样', async (t) => {
  const server = await startServer();
  t.after(() => stopServer(server));

  const existing = await postProduct(server.url, productPayload('保留商品', [
    priceSpec('黑色款', '59.00', 12),
    priceSpec('白色款', '69.5', 0), // 零库存与一位小数规范化都应原样保留
  ]));
  assert.equal(existing.status, 201);
  const before = await getProducts(server.url);
  assert.equal(before.length, 1);

  const rejected = await postProduct(server.url, productPayload('混合售价商品', [
    priceSpec('合法规格', '30.00', 4),
    priceSpec('中间合法规格', '0', 9),
    priceSpec('非法规格', '12.345', 7), // 多余小数
  ]));
  assert.equal(rejected.status, 400);
  const priceErrors = rejected.body.details.filter((detail: any) => detail.field === 'price');
  assert.deepEqual(
    priceErrors.map((detail: any) => detail.specIndex),
    [2],
    '只有非法售价的规格需要修正，合法规格不应被报价格错误',
  );

  const after = await getProducts(server.url);
  assert.deepEqual(after, before, '已有商品及其规格、售价和库存必须保持原样');
  assert.deepEqual(specByAttr(after[0], '黑色款'), {
    attributes: [{ name: '款式', value: '黑色款' }],
    price: '59.00',
    stock: 12,
  });
  assert.deepEqual(specByAttr(after[0], '白色款'), {
    attributes: [{ name: '款式', value: '白色款' }],
    price: '69.50',
    stock: 0,
  });
  assert.ok(
    after.every((product) => product.name !== '混合售价商品'),
    '合法规格不能单独留下，列表中不能出现被拒绝的商品',
  );
  assert.ok(
    !JSON.stringify(after).includes('合法规格') && !JSON.stringify(after).includes('中间合法规格'),
    '被拒商品中的合法规格也不能以任何形式残留',
  );
});

// ---------- 网页操作回归：动态规格表单的填写、删除、报错定位、内容保留与修正重提 ----------
//
// 上面的用例只验证接口与列表；这里用真实浏览器（headless Chrome + DevTools Protocol，
// 不引入第三方依赖）操作首页表单，保护用户遇到字段错误后的完整体验：
// 删除规格/属性后页面编号连续且提交载荷与当前页面一致；400 后停留在表单、保留全部输入、
// 错误原因与输入框标记精确对应当前留下的规格和属性；修正后直接重提即可成功。

interface CdpMessage {
  id?: number;
  method?: string;
  params?: any;
  result?: any;
  error?: any;
  sessionId?: string;
}

function findChrome(): string | undefined {
  if (process.env.CHROME_BIN) return process.env.CHROME_BIN;
  const probe = spawnSync(
    'sh',
    ['-c', 'command -v google-chrome google-chrome-stable chromium chromium-browser 2>/dev/null | head -n1'],
    { encoding: 'utf8' },
  );
  const found = typeof probe.stdout === 'string' ? probe.stdout.trim() : '';
  return found === '' ? undefined : found;
}

const CHROME_BIN = findChrome();
const CHROME_FLAGS = [
  '--headless=new',
  '--disable-gpu',
  '--no-sandbox',
  '--disable-dev-shm-usage',
  '--no-first-run',
  '--no-default-browser-check',
  '--disable-background-networking',
  '--disable-crash-reporter',
];

class CdpBrowser {
  private child: ChildProcess;
  private profileDir: string;
  private ws: WebSocket;
  private nextId = 1;
  private pending = new Map<number, { resolve: (v: any) => void; reject: (e: Error) => void; sessionId?: string }>();
  private listeners = new Map<string, (method: string, params: any) => void>();

  private constructor(child: ChildProcess, profileDir: string, ws: WebSocket) {
    this.child = child;
    this.profileDir = profileDir;
    this.ws = ws;
  }

  static async launch(): Promise<CdpBrowser> {
    const profileDir = mkdtempSync(join(tmpdir(), 'cartwell-chrome-'));
    const child = spawn(
      CHROME_BIN!,
      [...CHROME_FLAGS, '--remote-debugging-port=0', `--user-data-dir=${profileDir}`, 'about:blank'],
      { stdio: ['ignore', 'ignore', 'pipe'] },
    );
    let stderr = '';
    child.stderr!.setEncoding('utf8');
    child.stderr.on('data', (chunk: string) => { stderr += chunk; });

    const portFile = join(profileDir, 'DevToolsActivePort');
    const port = await new Promise<string>((resolve, reject) => {
      const started = Date.now();
      const timer = setInterval(() => {
        try {
          const line = readFileSync(portFile, 'utf8').split('\n')[0]!.trim();
          if (line) { clearInterval(timer); resolve(line); }
        } catch {
          if (Date.now() - started > 15_000) {
            clearInterval(timer);
            reject(new Error(`等待 Chrome 调试端口超时：${stderr.slice(-500)}`));
          }
        }
      }, 50);
    });

    const version = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json();
    const ws = new WebSocket(version.webSocketDebuggerUrl as string);
    await new Promise<void>((resolve, reject) => {
      ws.onopen = (): void => resolve();
      ws.onerror = (): void => reject(new Error('无法连接 Chrome DevTools Protocol'));
    });

    const browser = new CdpBrowser(child, profileDir, ws);
    ws.onmessage = (event: { data: string }): void => {
      const message: CdpMessage = JSON.parse(event.data);
      if (message.id !== undefined) {
        const entry = browser.pending.get(message.id);
        if (entry && (entry.sessionId === undefined || entry.sessionId === message.sessionId)) {
          browser.pending.delete(message.id);
          if (message.error) entry.reject(new Error(JSON.stringify(message.error)));
          else entry.resolve(message.result);
        }
        return;
      }
      if (message.method && message.sessionId) {
        browser.listeners.get(message.sessionId)?.(message.method, message.params);
      }
    };
    return browser;
  }

  send(method: string, params: Record<string, unknown> = {}, sessionId?: string): Promise<any> {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject, sessionId });
      this.ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
    });
  }

  async newPage(url: string): Promise<CdpPage> {
    const { targetId } = await this.send('Target.createTarget', { url: 'about:blank' });
    const { sessionId } = await this.send('Target.attachToTarget', { targetId, flatten: true });
    const page = new CdpPage(this, sessionId);
    this.listeners.set(sessionId, (method, params): void => {
      if (method === 'Fetch.requestPaused') page.handlePaused(params);
    });
    await this.send('Page.enable', {}, sessionId);
    await this.send('Runtime.enable', {}, sessionId);
    // 只拦截新增商品请求：在请求真正发出后暂停，便于核对载荷与提交过程中的按钮状态。
    await this.send('Fetch.enable', {
      patterns: [{ urlPattern: '*/api/products', requestStage: 'Request' }],
    }, sessionId);
    await this.send('Page.navigate', { url }, sessionId);
    await page.waitFor("document.getElementById('product-form') && document.querySelectorAll('#specs [data-spec]').length === 1");
    return page;
  }

  async close(): Promise<void> {
    try { this.ws.close(); } catch { /* 已关闭 */ }
    this.child.kill('SIGTERM');
    await Promise.race([
      once(this.child, 'exit'),
      new Promise((resolve) => setTimeout(resolve, 3000)),
    ]);
    if (this.child.exitCode === null) this.child.kill('SIGKILL');
    rmSync(this.profileDir, { recursive: true, force: true });
  }
}

class CdpPage {
  private browser: CdpBrowser;
  private sessionId: string;
  private readonly pausedQueue: any[] = [];
  private readonly pausedWaiters: Array<(params: any) => void> = [];

  constructor(browser: CdpBrowser, sessionId: string) {
    this.browser = browser;
    this.sessionId = sessionId;
  }

  handlePaused(params: any): void {
    const waiter = this.pausedWaiters.shift();
    if (waiter) waiter(params);
    else this.pausedQueue.push(params);
  }

  send(method: string, params: Record<string, unknown> = {}): Promise<any> {
    return this.browser.send(method, params, this.sessionId);
  }

  async eval(expression: string): Promise<any> {
    const result = await this.send('Runtime.evaluate', {
      expression,
      returnByValue: true,
      awaitPromise: true,
    });
    if (result.exceptionDetails) {
      throw new Error(`页面脚本执行失败：${result.exceptionDetails.text} ${result.exceptionDetails.exception?.description ?? ''}`);
    }
    return result.result.value;
  }

  // 轮询页面上的布尔条件；提交成功后的整页跳转也会经历短暂的上下文切换，忽略期间的异常。
  async waitFor(expression: string, timeoutMs = 8000, label?: string): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      try {
        if (await this.eval(expression)) return;
      } catch {
        if (Date.now() > deadline) throw new Error(`等待页面条件超时：${label ?? expression}`);
      }
      if (Date.now() > deadline) throw new Error(`等待页面条件超时：${label ?? expression}`);
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  }

  async waitPaused(timeoutMs = 8000): Promise<any> {
    const queued = this.pausedQueue.shift();
    if (queued) return queued;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const index = this.pausedWaiters.indexOf(resolve as any);
        if (index >= 0) this.pausedWaiters.splice(index, 1);
        reject(new Error('等待新增商品请求被拦截超时'));
      }, timeoutMs);
      this.pausedWaiters.push((params): void => { clearTimeout(timer); resolve(params); });
    });
  }

  continueRequest(requestId: string): Promise<any> {
    return this.send('Fetch.continueRequest', { requestId });
  }

  pausedCount(): number {
    return this.pausedQueue.length;
  }
}

// 点击提交、在请求被拦截时（服务端尚未响应）核对按钮状态，并返回浏览器实际发送的载荷。
// requestStage=Request 的暂停事件里 request.postData 就是浏览器实际发送的明文请求体。
async function submitAndHold(page: CdpPage): Promise<{ requestId: string; payload: any }> {
  await page.eval("document.getElementById('product-form').requestSubmit()");
  const paused = await page.waitPaused();
  assert.equal(paused.request.method, 'POST');
  assert.equal(
    await page.eval("document.getElementById('submit-btn').disabled"),
    true,
    '提交进行中提交按钮应暂时不可用',
  );
  assert.equal(
    await page.eval("Array.prototype.every.call(document.querySelectorAll('#product-form input, #product-form button'), function (el) { return el.disabled; })"),
    true,
    '提交进行中所有输入框与增删规格/属性按钮都应不可编辑、不可点击',
  );
  assert.match(
    await page.eval("document.getElementById('form-status').textContent"),
    /正在保存/,
    '提交进行中应显示正在保存提示，与字段校验失败区分开',
  );
  assert.equal(typeof paused.request.postData, 'string', '拦截事件应带实际发送的请求体');
  return { requestId: paused.requestId, payload: JSON.parse(paused.request.postData) };
}

// 读取表单当前完整状态：编号、各规格属性/售价/库存的输入值、错误文字与 invalid 标记。
const FORM_STATE_EXPR = `(function () {
  function inputState(row) {
    var n = row.querySelector('[data-attr-name]');
    var v = row.querySelector('[data-attr-value]');
    return {
      name: n.value,
      value: v.value,
      nameInvalid: n.classList.contains('invalid'),
      valueInvalid: v.classList.contains('invalid'),
      nameErr: row.querySelector('[data-err="attrName"]').textContent,
      valueErr: row.querySelector('[data-err="attrValue"]').textContent
    };
  }
  var status = document.getElementById('form-status');
  return {
    productName: document.querySelector('[data-name-input]').value,
    nameInvalid: document.querySelector('[data-name-input]').classList.contains('invalid'),
    nameErr: document.querySelector('[data-err="name"]').textContent,
    statusText: status.textContent,
    statusClass: status.className,
    numbers: Array.prototype.map.call(document.querySelectorAll('[data-spec-no]'), function (el) { return el.textContent; }),
    cards: Array.prototype.map.call(document.querySelectorAll('#specs [data-spec]'), function (card) {
      var price = card.querySelector('[data-price]');
      var stock = card.querySelector('[data-stock]');
      return {
        attrs: Array.prototype.map.call(card.querySelectorAll('.attr-row'), inputState),
        price: price.value,
        stock: stock.value,
        priceInvalid: price.classList.contains('invalid'),
        stockInvalid: stock.classList.contains('invalid'),
        priceErr: card.querySelector('[data-err="price"]').textContent,
        stockErr: card.querySelector('[data-err="stock"]').textContent,
        specErr: card.querySelector('[data-err="spec"]').textContent,
        attrsErr: card.querySelector('[data-err="attributes"]').textContent
      };
    })
  };
})()`;

const LIST_STATE_EXPR = `(function () {
  return {
    titles: Array.prototype.map.call(document.querySelectorAll('#product-list .product h3'), function (h3) { return h3.textContent; }),
    products: Array.prototype.map.call(document.querySelectorAll('#product-list .product'), function (product) {
      return {
        name: product.querySelector('h3').textContent,
        specs: Array.prototype.map.call(product.querySelectorAll('.spec-row'), function (row) {
          return {
            attrs: Array.prototype.map.call(row.querySelectorAll('.attr'), function (attr) { return attr.textContent; }),
            price: row.querySelector('.price').textContent,
            stock: row.querySelector('.stock').textContent,
            outOfStock: !!row.querySelector('.badge-oos')
          };
        })
      };
    })
  };
})()`;

// 按真实用户路径填表：名称、三条规格各有两个属性，再删除中间的整条规格和第一条规格里靠前的属性。
const FILL_AND_DELETE_EXPR = `(function () {
  document.querySelector('[data-name-input]').value = '  秋冬卫衣  ';
  document.getElementById('add-spec').click();
  document.getElementById('add-spec').click();
  var cards = document.querySelectorAll('#specs [data-spec]');
  function fill(card, attributeRows, price, stock) {
    for (var i = card.querySelectorAll('.attr-row').length; i < attributeRows.length; i++) {
      card.querySelector('.add-attr').click();
    }
    var rows = card.querySelectorAll('.attr-row');
    attributeRows.forEach(function (pair, index) {
      rows[index].querySelector('[data-attr-name]').value = pair[0];
      rows[index].querySelector('[data-attr-value]').value = pair[1];
    });
    card.querySelector('[data-price]').value = price;
    card.querySelector('[data-stock]').value = stock;
  }
  // 规格 1：颜色/红色（稍后删除）+ 尺码/纯空白值（保留，首次提交因此被拒绝）
  fill(cards[0], [['颜色', '红色'], ['尺码', '   ']], '88.00', '6');
  // 规格 2：稍后整条删除，它的属性、售价、库存都不能被带上
  fill(cards[1], [['颜色', '蓝色'], ['尺码', 'L']], '55.50', '2');
  // 规格 3：保留，售价 12.345 不合规，库存为零
  fill(cards[2], [['颜色', '绿色'], ['尺码', '均码']], '12.345', '0');
  // 删除整条中间规格，再删除第一条规格中靠前的属性
  cards[1].querySelector('.remove-spec').click();
  cards[0].querySelectorAll('.remove-attr')[0].click();
  return document.querySelectorAll('#specs [data-spec]').length;
})()`;

test('网页：删除规格与属性后提交与当前页面一致；字段错误精确定位并保留输入；修正后直接重提成功', async (t) => {
  if (!CHROME_BIN) { t.skip('未找到 Chrome/Chromium，跳过网页操作回归'); return; }

  const server = await startServer();
  t.after(() => stopServer(server));
  const browser = await CdpBrowser.launch();
  t.after(() => browser.close());

  // 先经接口放一件已有商品：失败提交不能影响它，成功后新商品应排在它前面。
  const existing = await postProduct(server.url, productPayload('已有商品', [
    spec([['颜色', '黑色']], '59.00', 12),
  ]));
  assert.equal(existing.status, 201);
  const listBefore = await getProducts(server.url);

  const page = await browser.newPage(`${server.url}/`);
  assert.deepEqual(
    await page.eval(LIST_STATE_EXPR).then((s) => s.titles),
    ['已有商品'],
    '首页应展示已存在的商品',
  );

  assert.equal(await page.eval(FILL_AND_DELETE_EXPR), 2, '删除整条规格后应只剩两张规格卡片');
  assert.deepEqual(
    await page.eval("Array.prototype.map.call(document.querySelectorAll('[data-spec-no]'), function (el) { return el.textContent; })"),
    ['规格 1', '规格 2'],
    '删除中间规格后，剩余规格的显示编号必须连续重新编号',
  );

  // ---- 第一次提交：浏览器实际发出的载荷必须与删除后页面上剩余的内容逐字段一致 ----
  const first = await submitAndHold(page);
  assert.deepEqual(first.payload, {
    name: '  秋冬卫衣  ',
    specs: [
      { attributes: [{ name: '尺码', value: '   ' }], price: '88.00', stock: 6 },
      {
        attributes: [
          { name: '颜色', value: '绿色' },
          { name: '尺码', value: '均码' },
        ],
        price: '12.345',
        stock: 0,
      },
    ],
  }, '被删除的规格与属性不能带上；保留的属性、售价、库存必须仍属于原来的规格，不能串位');

  // 等待响应期间尝试修改与增删：表单必须保持与本次发送的载荷一致，不产生第二次提交
  assert.deepEqual(
    await page.eval(`(function () {
      var cards = document.querySelectorAll('#specs [data-spec]');
      // disabled 的输入框无法获得焦点，用户键入不会落到其中
      var nameInput = document.querySelector('[data-name-input]');
      var priceInput = cards[1].querySelector('[data-price]');
      nameInput.focus();
      var nameFocusable = document.activeElement === nameInput;
      priceInput.focus();
      var priceFocusable = document.activeElement === priceInput;
      // 浏览器对 disabled 按钮的真实点击（含 click() 程序化触发）一律不派发事件
      cards[0].querySelector('.remove-attr').click();
      cards[1].querySelector('.remove-spec').click();
      document.getElementById('add-spec').click();
      cards[0].querySelector('.add-attr').click();
      return {
        allControlsDisabled: Array.prototype.every.call(
          document.querySelectorAll('#product-form input, #product-form button'),
          function (el) { return el.disabled; }
        ),
        nameFocusable: nameFocusable,
        priceFocusable: priceFocusable,
        specCount: document.querySelectorAll('#specs [data-spec]').length,
        firstSpecAttrCount: cards[0].querySelectorAll('.attr-row').length,
        secondSpecAttrCount: cards[1].querySelectorAll('.attr-row').length
      };
    })()`),
    {
      allControlsDisabled: true,
      nameFocusable: false,
      priceFocusable: false,
      specCount: 2,
      firstSpecAttrCount: 1,
      secondSpecAttrCount: 2,
    },
    '等待期间输入框不能聚焦编辑，删规格、删属性、加规格、加属性都不能改变表单',
  );
  // 等待期间回车或重复触发提交都不能发起第二次请求（首个暂停事件已被取走，队列应为空）
  await page.eval(`(function () {
    var f = document.getElementById('product-form');
    f.requestSubmit();
    f.requestSubmit();
    f.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
  })()`);
  await new Promise((resolve) => setTimeout(resolve, 100));
  assert.equal(page.pausedCount(), 0, '等待结果期间不能再次发起提交');
  await page.continueRequest(first.requestId);

  await page.waitFor(
    "document.getElementById('form-status').className.indexOf('error') >= 0",
    8000,
    '首次提交失败后应显示错误状态',
  );
  assert.equal(
    await page.eval("document.getElementById('submit-btn').disabled"),
    false,
    '失败响应结束后提交按钮应恢复可用',
  );

  const state = await page.eval(FORM_STATE_EXPR);
  assert.match(state.statusText, /未创建/, '页面应明确说明商品没有创建');
  assert.equal(state.productName, '  秋冬卫衣  ', '商品名称原文（含首尾空白）应保留在输入框');
  assert.equal(state.nameInvalid, false, '合法的商品名称不应被标记为错误');
  assert.equal(state.nameErr, '');
  assert.deepEqual(state.numbers, ['规格 1', '规格 2'], '失败后编号仍连续，表单停留在当前页面');

  assert.equal(state.cards.length, 2);
  // 留下的第 1 条规格：唯一属性是空白值，错误必须落在该属性值上
  assert.deepEqual(state.cards[0].attrs, [
    {
      name: '尺码', value: '   ',
      nameInvalid: false, valueInvalid: true,
      nameErr: '', valueErr: '属性值不能为空',
    },
  ], '空白属性值旁应显示原因并标出该输入框；属性名称合法不应被连带标记');
  assert.equal(state.cards[0].price, '88.00', '合法售价原样保留');
  assert.equal(state.cards[0].stock, '6', '库存原样保留');
  assert.equal(state.cards[0].priceInvalid, false, '合法规格的售价不应被标记为同类错误');
  assert.equal(state.cards[0].priceErr, '');
  assert.equal(state.cards[0].stockInvalid, false);
  // 留下的第 2 条规格（原第 3 条）：12.345 售价错误要跟随规格定位到新编号的卡片
  assert.deepEqual(state.cards[1].attrs.map((a: any) => [a.name, a.value, a.nameInvalid, a.valueInvalid]), [
    ['颜色', '绿色', false, false],
    ['尺码', '均码', false, false],
  ], '保留规格的属性值不串位，且合法属性不应被标记');
  assert.equal(state.cards[1].price, '12.345', '非法售价原文保留，等待用户修正');
  assert.equal(state.cards[1].stock, '0', '零库存输入保留，不会因提交失败被丢弃');
  assert.equal(state.cards[1].priceInvalid, true, '售价输入框应被标出');
  assert.match(state.cards[1].priceErr, /售价/, '售价旁应显示具体原因');
  assert.equal(state.cards[1].stockInvalid, false);
  assert.equal(state.cards[1].stockErr, '');
  assert.doesNotMatch(
    JSON.stringify(state),
    /蓝色|红色|55\.50/,
    '已删除的规格内容（蓝色/红色及其售价）不能残留在表单状态中',
  );

  const listAfterFailure = await page.eval(LIST_STATE_EXPR);
  assert.deepEqual(listAfterFailure.titles, ['已有商品'], '失败停留在表单，已有商品列表保持不变');
  assert.deepEqual(await getProducts(server.url), listBefore, '接口侧也不能产生新记录或改动已有商品');

  // ---- 只改两处错误：空白属性值改成合规内容、12.345 改成一位小数；不重添规格、不重填名称 ----
  await page.eval(`(function () {
    var cards = document.querySelectorAll('#specs [data-spec]');
    cards[0].querySelectorAll('.attr-row')[0].querySelector('[data-attr-value]').value = '  L码  ';
    cards[1].querySelector('[data-price]').value = '12.3';
  })()`);

  const second = await submitAndHold(page);
  // 再次提交时旧错误应先被清除并进入等待状态：请求被拦截时服务端还没返回，
  // 页面应显示「正在保存」，且不应残留任何错误文字或标记
  const cleared = await page.eval(FORM_STATE_EXPR);
  assert.match(cleared.statusText, /正在保存/, '等待结果期间应显示正在保存提示');
  assert.equal(cleared.statusClass, 'saving', '等待状态应与字段校验失败的错误样式区分开');
  assert.equal(
    await page.eval("document.querySelectorAll('#product-form .invalid').length"),
    0,
    '再次提交时旧的错误标记应被清除',
  );
  assert.equal(
    await page.eval("Array.prototype.filter.call(document.querySelectorAll('#product-form .err'), function (s) { return s.textContent !== ''; }).length"),
    0,
    '再次提交时旧的错误文字应被清除',
  );
  assert.deepEqual(second.payload, {
    name: '  秋冬卫衣  ',
    specs: [
      { attributes: [{ name: '尺码', value: '  L码  ' }], price: '88.00', stock: 6 },
      {
        attributes: [
          { name: '颜色', value: '绿色' },
          { name: '尺码', value: '均码' },
        ],
        price: '12.3',
        stock: 0,
      },
    ],
  }, '无须重新添加规格或重填名称；修正后的载荷与当前页面一致');
  await page.continueRequest(second.requestId);

  // 成功后返回首页：整页重新加载（输入框被重置），新商品排在已有商品之前
  await page.waitFor(
    "document.querySelector('[data-name-input]').value === '' && document.querySelectorAll('#product-list .product').length === 2",
    8000,
    '提交成功后应返回首页并展示两件商品',
  );
  const list = await page.eval(LIST_STATE_EXPR);
  assert.deepEqual(list.titles, ['秋冬卫衣', '已有商品'], '新商品排在已有商品之前，名称按去除首尾空白展示');
  assert.deepEqual(list.products[0], {
    name: '秋冬卫衣',
    specs: [
      { attrs: ['尺码：L码'], price: '¥88.00', stock: '库存 6', outOfStock: false },
      { attrs: ['颜色：绿色', '尺码：均码'], price: '¥12.30', stock: '库存 0', outOfStock: true },
    ],
  }, '保留的规格按修正后内容展示：属性去空白、售价两位小数；零库存规格仍保存并标记缺货');

  const products = await getProducts(server.url);
  assert.equal(products.length, 2);
  assert.equal(products[0].name, '秋冬卫衣');
  assert.deepEqual(products[0].specs, [
    { attributes: [{ name: '尺码', value: 'L码' }], price: '88.00', stock: 6 },
    {
      attributes: [
        { name: '颜色', value: '绿色' },
        { name: '尺码', value: '均码' },
      ],
      price: '12.30',
      stock: 0,
    },
  ], '接口保存的内容与页面展示一致，零库存规格未因前一次失败被丢弃');
  assert.deepEqual(products[1], listBefore[0], '已有商品的规格、售价和库存始终保持原样');
  assert.equal(products[1].id, existing.body.id);
});

test('网页：删除最前面的规格后编号连续，售价错误定位到重编号后剩下的规格；修正即成功', async (t) => {
  if (!CHROME_BIN) { t.skip('未找到 Chrome/Chromium，跳过网页操作回归'); return; }

  const server = await startServer();
  t.after(() => stopServer(server));
  const browser = await CdpBrowser.launch();
  t.after(() => browser.close());

  const page = await browser.newPage(`${server.url}/`);
  await page.eval(`(function () {
    document.querySelector('[data-name-input]').value = '删除首规格商品';
    document.getElementById('add-spec').click();
    var cards = document.querySelectorAll('#specs [data-spec]');
    cards[0].querySelector('[data-attr-name]').value = '颜色';
    cards[0].querySelector('[data-attr-value]').value = '红色';
    cards[0].querySelector('[data-price]').value = '10.00';
    cards[0].querySelector('[data-stock]').value = '1';
    cards[1].querySelector('[data-attr-name]').value = '颜色';
    cards[1].querySelector('[data-attr-value]').value = '蓝色';
    cards[1].querySelector('[data-price]').value = '12.345';
    cards[1].querySelector('[data-stock]').value = '3';
    // 删除最前面的规格
    cards[0].querySelector('.remove-spec').click();
  })()`);

  assert.deepEqual(
    await page.eval("Array.prototype.map.call(document.querySelectorAll('[data-spec-no]'), function (el) { return el.textContent; })"),
    ['规格 1'],
    '删除最前面的规格后，剩下规格显示为规格 1',
  );

  const first = await submitAndHold(page);
  assert.deepEqual(first.payload, {
    name: '删除首规格商品',
    specs: [
      { attributes: [{ name: '颜色', value: '蓝色' }], price: '12.345', stock: 3 },
    ],
  }, '提交只能包含剩下的这条规格，被删除规格的红色/10.00/1 不能串到它上面');
  await page.continueRequest(first.requestId);

  await page.waitFor(
    "document.getElementById('form-status').className.indexOf('error') >= 0",
    8000,
    '提交失败后应显示错误状态',
  );
  const state = await page.eval(FORM_STATE_EXPR);
  assert.match(state.statusText, /未创建/);
  assert.equal(state.cards.length, 1);
  assert.deepEqual(state.numbers, ['规格 1']);
  assert.equal(state.cards[0].price, '12.345', '非法售价保留在剩下的规格上');
  assert.equal(state.cards[0].priceInvalid, true, '错误应标记在重编号后剩下的规格的售价上');
  assert.match(state.cards[0].priceErr, /售价/);
  assert.equal(state.cards[0].attrs[0].value, '蓝色');
  assert.equal(state.cards[0].attrs[0].valueInvalid, false, '合法属性值不应被标记为售价同类错误');
  assert.doesNotMatch(JSON.stringify(state), /红色/, '已删除规格的属性值不能残留在表单中');

  await page.eval("document.querySelector('#specs [data-spec] [data-price]').value = '12.34'");
  const second = await submitAndHold(page);
  assert.equal(
    await page.eval("document.querySelectorAll('#product-form .invalid').length"),
    0,
    '再次提交时旧标记应已清除',
  );
  await page.continueRequest(second.requestId);

  await page.waitFor(
    "document.querySelector('[data-name-input]').value === '' && document.querySelectorAll('#product-list .product').length === 1",
    8000,
    '修正后提交应成功并返回首页',
  );
  const list = await page.eval(LIST_STATE_EXPR);
  assert.deepEqual(list.products, [{
    name: '删除首规格商品',
    specs: [{ attrs: ['颜色：蓝色'], price: '¥12.34', stock: '库存 3', outOfStock: false }],
  }]);
});
