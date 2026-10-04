import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
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

function priceErrors(details: any[]): any[] {
  return details.filter((detail) => detail.field === 'price');
}

test('合法售价规范化为两位小数字符串：零、整数、一位/两位小数和前导零都按字符串处理', async (t) => {
  const server = await startServer();
  t.after(() => stopServer(server));

  const cases = [
    { label: '零', raw: '0', expected: '0.00' },
    { label: '整数', raw: '12', expected: '12.00' },
    { label: '一位小数', raw: '12.5', expected: '12.50' },
    { label: '已有两位小数', raw: '12.50', expected: '12.50' },
    { label: '多个前导零', raw: '00012.30', expected: '12.30' },
  ];

  const result = await postProduct(server.url, productPayload('金额规范化商品',
    cases.map((item) => spec([['款型', item.label]], item.raw, 3)),
  ));
  assert.equal(result.status, 201);
  assert.equal(result.body.specs.length, cases.length);

  cases.forEach((item, index) => {
    const price = result.body.specs[index].price;
    assert.equal(typeof price, 'string', `「${item.raw}」规范化后售价仍是字符串`);
    assert.equal(price, item.expected, `「${item.raw}」应保存为「${item.expected}」`);
    assert.match(price, /^\d+\.\d{2}$/, '金额必须恰好两位小数、不带指数或多余小数');
  });

  const products = await getProducts(server.url);
  assert.equal(products.length, 1);
  assert.deepEqual(products[0], result.body, '列表记录应与创建响应完全一致，含规范化后的金额');
});

test('同一商品不同规格使用不同合法金额时，规范化结果各自对应原属性组合，不互相覆盖或交换', async (t) => {
  const server = await startServer();
  t.after(() => stopServer(server));

  const result = await postProduct(server.url, productPayload('多规格金额商品', [
    spec([['颜色', '红']], '0', 1),
    spec([['颜色', '绿']], '8.5', 2),
    spec([['颜色', '蓝']], '99.00', 3),
    spec([['颜色', '白']], '00012.30', 4),
  ]));
  assert.equal(result.status, 201);

  // 规格顺序保持，金额与属性组合、库存一一对应
  assert.deepEqual(
    result.body.specs.map((specRecord: any) => [specRecord.attributes[0].value, specRecord.price, specRecord.stock]),
    [['红', '0.00', 1], ['绿', '8.50', 2], ['蓝', '99.00', 3], ['白', '12.30', 4]],
  );

  const products = await getProducts(server.url);
  assert.deepEqual(
    products[0].specs.map((specRecord: any) => [specRecord.attributes[0].value, specRecord.price, specRecord.stock]),
    [['红', '0.00', 1], ['绿', '8.50', 2], ['蓝', '99.00', 3], ['白', '12.30', 4]],
    '查询到的规格金额也必须对应原属性组合，不能串行或互换',
  );
});

test('整数部分超过 JavaScript 安全整数范围的两位小数金额，在创建响应和列表查询中逐位保留', async (t) => {
  const server = await startServer();
  t.after(() => stopServer(server));

  const bigPrices = ['9007199254740993.01', '9007199254740993.02'];
  assert.ok(!Number.isSafeInteger(Number(bigPrices[0].split('.')[0])), '测试前提：整数部分超出安全整数范围');

  const result = await postProduct(server.url, productPayload('大额商品', [
    spec([['款型', '标准']], bigPrices[0], 9),
    spec([['款型', '加价']], bigPrices[1], 1),
  ]));
  assert.equal(result.status, 201, '超出安全整数范围的合法金额应创建成功');

  bigPrices.forEach((expected, index) => {
    const price = result.body.specs[index].price;
    assert.equal(typeof price, 'string', '售价必须是字符串，不能被解析成数字');
    assert.equal(price, expected, '每一位数字都必须保留，不能丢位');
    assert.doesNotMatch(price, /[eE]/, '不能变成指数形式');
    assert.match(price, /^\d{16}\.\d{2}$/, '不能多出或缺少小数位');
  });

  // 在线路原文上也要逐位出现该字符串，排除任何数字转换
  const rawList = await (await fetch(`${server.url}/api/products`)).text();
  for (const expected of bigPrices) {
    assert.ok(rawList.includes(`"price":"${expected}"`), `查询响应原文应逐位包含 ${expected}`);
  }

  const products = await getProducts(server.url);
  assert.equal(products.length, 1);
  assert.deepEqual(products[0].specs, result.body.specs, '列表中的大额金额与创建结果一致');
});

test('不合规售价返回 400，details 明确指出出错的规格位置与 price 字段，商品不被创建', async (t) => {
  const server = await startServer();
  t.after(() => stopServer(server));

  // 商品名称、属性、库存和请求体大小都合规，仅售价不合规
  const cases: Array<{ label: string; price: unknown }> = [
    { label: '负数', price: '-12' },
    { label: '负数零头', price: '-0.01' },
    { label: '指数写法（小写）', price: '1e3' },
    { label: '指数写法（大写）', price: '1E3' },
    { label: '千位分隔符', price: '1,000.00' },
    { label: '超过两位小数', price: '12.345' },
    { label: '售价作为 JSON 数字（整数）', price: 12 },
    { label: '售价作为 JSON 数字（小数）', price: 12.5 },
    { label: '售价作为 JSON 数字（零）', price: 0 },
    { label: '空字符串', price: '' },
    { label: '空值 null', price: null },
  ];

  for (const item of cases) {
    const result = await postProduct(server.url, productPayload('非法售价商品', [
      spec([['颜色', '红色']], item.price as string, 5),
    ]));
    assert.equal(result.status, 400, `「${item.label}」应被拒绝`);
    assert.equal(result.body.error, '商品校验未通过，未创建任何记录');
    const errors = priceErrors(result.body.details);
    assert.equal(errors.length, 1, `「${item.label}」应恰有一条售价错误`);
    assert.equal(errors[0].field, 'price', '错误应指明是售价字段');
    assert.equal(errors[0].specIndex, 0, '错误应指明出错的规格');
    assert.equal(errors[0].path, 'specs[0].price');
    assert.match(errors[0].message, /售价|金额/);
    assert.notEqual(errors[0].message, '');
  }

  assert.deepEqual(await getProducts(server.url), [], '所有非法售价提交都不能留下商品记录');
});

test('售价 "12.345" 不会通过四舍五入、截断或默认值变成可保存金额', async (t) => {
  const server = await startServer();
  t.after(() => stopServer(server));

  const result = await postProduct(server.url, productPayload('三位小数商品', [
    spec([['颜色', '红色']], '12.345', 5),
  ]));
  assert.equal(result.status, 400);
  const errors = priceErrors(result.body.details);
  assert.equal(errors.length, 1);
  assert.equal(errors[0].path, 'specs[0].price');

  const products = await getProducts(server.url);
  assert.deepEqual(products, [], '三位小数不能被保存');
  const serialized = JSON.stringify(products);
  for (const approximated of ['12.35', '12.34']) {
    assert.ok(!serialized.includes(approximated), `不能把 12.345 近似保存成 ${approximated}`);
  }
  assert.ok(!serialized.includes('"0.00"'), '不能套用默认零金额保存');
});

test('多条规格同时有不合规售价时，details 分别指出每条需要修正的规格位置', async (t) => {
  const server = await startServer();
  t.after(() => stopServer(server));

  const prices: unknown[] = ['-9', '10.00', '1e3', 5, ''];
  const result = await postProduct(server.url, productPayload('多规格非法售价商品',
    prices.map((price, index) => spec([['颜色', `颜色${index}`]], price as string, 6)),
  ));

  assert.equal(result.status, 400);
  const errors = priceErrors(result.body.details);
  assert.equal(result.body.details.length, 4, '其他字段均合规，应只有四条售价错误');
  assert.deepEqual(
    errors.map((detail) => detail.specIndex),
    [0, 2, 3, 4],
    '每条不合规售价的规格下标都应被指出，合法规格不在其中',
  );
  assert.deepEqual(
    errors.map((detail) => detail.path),
    ['specs[0].price', 'specs[2].price', 'specs[3].price', 'specs[4].price'],
  );
  assert.ok(errors.every((detail) => detail.field === 'price' && detail.message !== ''));

  assert.deepEqual(await getProducts(server.url), [], '被拒绝的商品不能留下记录');
});

test('同一商品混有合法与非法售价规格时整个商品都不创建，已有商品的完整记录、售价和库存保持原样', async (t) => {
  const server = await startServer();
  t.after(() => stopServer(server));

  const existing = await postProduct(server.url, productPayload('已有商品', [
    spec([['颜色', '黑色'], ['尺码', 'S']], '59.00', 12),
    spec([['颜色', '黑色'], ['尺码', 'M']], '69.5', 0),
  ]));
  assert.equal(existing.status, 201);
  const before = await getProducts(server.url);
  assert.equal(before.length, 1);

  const rejected = await postProduct(server.url, productPayload('新商品', [
    spec([['颜色', '蓝色']], '30.00', 4), // 售价合法的规格也不能单独留下
    spec([['颜色', '绿色']], '-1', 9),
    spec([['颜色', '白色']], '12.345', 2),
  ]));
  assert.equal(rejected.status, 400);
  assert.deepEqual(
    priceErrors(rejected.body.details).map((detail) => detail.specIndex).sort(),
    [1, 2],
    '错误详情只指向售价不合规的规格',
  );

  const after = await getProducts(server.url);
  assert.deepEqual(after, before, '已有商品的完整记录、售价和库存应保持原样');
  assert.ok(
    after.every((product) => product.name !== '新商品'),
    '整个商品（包括其中售价合法的规格）都不能被创建',
  );
  assert.ok(!JSON.stringify(after).includes('蓝色'), '合法规格不能单独留下');
});
