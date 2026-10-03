import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';

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
