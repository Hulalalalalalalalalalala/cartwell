// 新增商品「同一商品内重复规格」判定的回归测试。
//
// 以公开 HTTP 接口为观察入口：POST /api/products 的状态码与响应体、GET /api/products
// 保存后的商品列表。重复判定只比较规格内全部属性名称与值（去首尾空白、顺序无关、
// 大小写敏感），售价与库存不参与；后续调整商品校验时，这些用例应继续通过。
import { beforeEach, afterEach, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { ChildProcessWithoutNullStreams } from 'node:child_process';

interface Attribute {
  name: string;
  value: string;
}
interface Spec {
  attributes: Attribute[];
  price: string;
  stock: number;
}
interface Product {
  id: string;
  name: string;
  specs: Spec[];
  createdAt: string;
}
interface Detail {
  path: string;
  field: string;
  message: string;
  specIndex?: number;
  attributeIndex?: number;
}
interface ErrorBody {
  error: string;
  details?: Detail[];
}

const SERVER_TS = fileURLToPath(new URL('./server.ts', import.meta.url));

interface ServerHandle {
  origin: string;
  stop: () => Promise<void>;
}

// 每个用例使用独立的数据目录和端口（--port 0 自动选取），互不干扰。
function startServer(): Promise<ServerHandle> {
  const dataDir = mkdtempSync(join(tmpdir(), 'cartwell-test-'));
  const child: ChildProcessWithoutNullStreams = spawn(
    process.execPath,
    [SERVER_TS, 'serve', '--host', '127.0.0.1', '--port', '0', '--data-dir', dataDir],
    { stdio: ['ignore', 'pipe', 'pipe'] },
  );
  let output = '';
  const stop = (): Promise<void> => new Promise((resolve) => {
    child.once('exit', () => {
      rmSync(dataDir, { recursive: true, force: true });
      resolve();
    });
    child.kill('SIGTERM');
  });
  return new Promise<ServerHandle>((resolve, reject) => {
    child.stdout.on('data', (chunk: Buffer) => {
      output += chunk.toString('utf8');
      const match = output.match(/http:\/\/[^/:]+:(\d+)/);
      if (match) resolve({ origin: `http://127.0.0.1:${match[1]}`, stop });
    });
    child.on('exit', (code) => reject(new Error(`测试服务器提前退出，退出码 ${code}`)));
  });
}

let origin = '';
let stopServer: () => Promise<void>;

beforeEach(async () => {
  const handle = await startServer();
  origin = handle.origin;
  stopServer = handle.stop;
});
afterEach(async () => {
  await stopServer();
});

async function postProduct(payload: unknown): Promise<{ status: number; body: ErrorBody & Record<string, unknown> }> {
  const response = await fetch(`${origin}/api/products`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  });
  return { status: response.status, body: (await response.json()) as ErrorBody & Record<string, unknown> };
}

async function getProducts(): Promise<Product[]> {
  const response = await fetch(`${origin}/api/products`);
  assert.equal(response.status, 200);
  const body = (await response.json()) as { products: Product[] };
  return body.products;
}

// 构造一条规格，减少样板代码。
function spec(attributes: Attribute, price: string, stock: number): Spec {
  return { attributes: [attributes], price, stock };
}
function specMulti(attributes: Attribute[], price: string, stock: number): Spec {
  return { attributes, price, stock };
}

test('属性填写顺序不同但名称和值完全相同的两条规格仍判定为重复', async () => {
  const result = await postProduct({
    name: '顺序测试商品',
    specs: [
      specMulti([{ name: '颜色', value: '红色' }, { name: '尺码', value: 'M' }], '99.00', 20),
      // 第二条先填写尺码，售价与库存也与第一条不同。
      specMulti([{ name: '尺码', value: 'M' }, { name: '颜色', value: '红色' }], '10.5', 3),
    ],
  });

  assert.equal(result.status, 400);
  assert.equal(result.body.error, '商品校验未通过，未创建任何记录');
  // details 同时指出两条冲突规格的位置，调用者可直接定位。
  assert.deepEqual(result.body.details, [
    { path: 'specs[0]', field: 'spec', specIndex: 0, message: '与第 2 条规格的属性名称和值完全相同' },
    { path: 'specs[1]', field: 'spec', specIndex: 1, message: '与第 1 条规格的属性名称和值完全相同（调换属性顺序也算重复）' },
  ]);

  // 被拒绝的商品没有留下任何记录。
  assert.deepEqual(await getProducts(), []);
});

test('属性名称或值带有的首尾空白在比较前去除，不能绕过重复限制', async () => {
  const result = await postProduct({
    name: '空白测试商品',
    specs: [
      specMulti([{ name: '颜色', value: '红色' }, { name: '尺码', value: 'M' }], '50.00', 5),
      // 调换顺序且所有文字都带首尾空白，去空白后与第一条完全一致。
      specMulti([{ name: ' 尺码 ', value: ' M ' }, { name: '颜色 ', value: ' 红色 ' }], '50.00', 5),
    ],
  });

  assert.equal(result.status, 400);
  assert.deepEqual(result.body.details, [
    { path: 'specs[0]', field: 'spec', specIndex: 0, message: '与第 2 条规格的属性名称和值完全相同' },
    { path: 'specs[1]', field: 'spec', specIndex: 1, message: '与第 1 条规格的属性名称和值完全相同（调换属性顺序也算重复）' },
  ]);
  assert.deepEqual(await getProducts(), []);
});

test('同一商品里合法规格与重复规格并存时，整个商品都不保存', async () => {
  const result = await postProduct({
    name: '混合提交商品',
    specs: [
      spec({ name: '颜色', value: '蓝色' }, '5.00', 7), // 合法，不应被单独保存
      specMulti([{ name: '颜色', value: '红色' }, { name: '尺码', value: 'M' }], '9.00', 2),
      specMulti([{ name: '尺码', value: 'M ' }, { name: '颜色', value: '红色  ' }], '100.00', 99),
    ],
  });

  assert.equal(result.status, 400);
  // details 指向真正冲突的第 2、3 条规格（1 起位置说明）。
  assert.deepEqual(result.body.details, [
    { path: 'specs[1]', field: 'spec', specIndex: 1, message: '与第 3 条规格的属性名称和值完全相同' },
    { path: 'specs[2]', field: 'spec', specIndex: 2, message: '与第 2 条规格的属性名称和值完全相同（调换属性顺序也算重复）' },
  ]);

  // 不能只留下其中合法的部分。
  assert.deepEqual(await getProducts(), []);
});

test('重复规格被拒绝后，已有商品及其规格、售价和库存保持原样', async () => {
  const seed = await postProduct({
    name: '已有商品',
    specs: [
      specMulti([{ name: '颜色', value: '红色' }, { name: '尺码', value: 'M' }], '12.3', 2),
      specMulti([{ name: '颜色', value: '蓝色' }, { name: '尺码', value: 'L' }], '0', 0),
    ],
  });
  assert.equal(seed.status, 201);

  const rejected = await postProduct({
    name: '不应保存的商品',
    specs: [
      spec({ name: '颜色', value: '红色' }, '99.00', 10),
      spec({ name: '颜色', value: ' 红色 ' }, '88.00', 11), // 去空白后与上一条重复
    ],
  });
  assert.equal(rejected.status, 400);

  const products = await getProducts();
  assert.equal(products.length, 1);
  // 列表中仍是被拒绝前保存的完整记录（含金额两位小数与零库存）。
  assert.deepEqual(products[0], seed.body as unknown as Product);
  assert.equal(products[0].name, '已有商品');
  assert.deepEqual(products[0].specs, [
    { attributes: [{ name: '颜色', value: '红色' }, { name: '尺码', value: 'M' }], price: '12.30', stock: 2 },
    { attributes: [{ name: '颜色', value: '蓝色' }, { name: '尺码', value: 'L' }], price: '0.00', stock: 0 },
  ]);
});

test('属性值不同、属性数量不同或大小写不同的规格允许共存', async () => {
  const result = await postProduct({
    name: '  帽子  ', // 名称空白保存时去除
    specs: [
      specMulti([{ name: '颜色', value: '红色' }, { name: '尺码', value: 'M' }], '1', 1),
      specMulti([{ name: '颜色', value: '红色' }, { name: '尺码', value: 'L' }], '1.5', 2),
      spec({ name: ' 颜色 ', value: ' 红色 ' }, '0', 0), // 少一个属性，不视为重复；零价零库存合法，文字空白保存时去除
      specMulti([{ name: '颜色', value: '红色' }, { name: '尺码', value: 'm' }], '1', 1), // 值大小写敏感
      specMulti([{ name: '颜色', value: '红色' }, { name: 'size', value: 'M' }], '1', 1), // 属性名称大小写敏感
    ],
  });

  assert.equal(result.status, 201);
  const created = result.body as unknown as Product;
  assert.equal(created.name, '帽子');
  assert.equal(created.specs.length, 5);
  // 金额统一为两位小数；属性文字空白在保存前去除。
  assert.deepEqual(created.specs.map((s) => s.price), ['1.00', '1.50', '0.00', '1.00', '1.00']);
  assert.deepEqual(created.specs.map((s) => s.stock), [1, 2, 0, 1, 1]);
  assert.equal(created.specs[3].attributes[1].value, 'm');
  assert.equal(created.specs[4].attributes[1].name, 'size');

  const products = await getProducts();
  assert.equal(products.length, 1);
  assert.deepEqual(products[0], created); // 列表记录与 201 返回一致
});

test('重复限制只作用于同一次新增：不同商品可复用相同规格，同名也不扩大范围', async () => {
  const first = await postProduct({
    name: '基础T恤',
    specs: [specMulti([{ name: '颜色', value: '红色' }, { name: '尺码', value: 'M' }], '99.00', 20)],
  });
  assert.equal(first.status, 201);

  // 同名商品、相同规格（属性顺序相反、售价库存不同）仍允许创建。
  const second = await postProduct({
    name: '基础T恤',
    specs: [specMulti([{ name: '尺码', value: 'M' }, { name: '颜色', value: '红色' }], '88', 5)],
  });
  assert.equal(second.status, 201);
  const created = second.body as unknown as Product;
  assert.equal(typeof created.id, 'string');
  assert.ok(!Number.isNaN(Date.parse(created.createdAt)));
  assert.equal(created.specs[0].price, '88.00');

  const products = await getProducts();
  assert.deepEqual(products.map((p) => p.id), [(second.body as Product).id, (first.body as Product).id]);
});

test('合法请求返回 201 完整商品记录，之后从列表查到且新商品排在最前', async () => {
  const names = ['第一件', '第二件', '第三件'];
  const created: Product[] = [];
  for (const name of names) {
    const result = await postProduct({ name, specs: [spec({ name: '颜色', value: '红色' }, '10.00', 1)] });
    assert.equal(result.status, 201);
    created.push(result.body as unknown as Product);
  }

  const products = await getProducts();
  assert.deepEqual(products.map((p) => p.id), created.map((p) => p.id).reverse());
  assert.deepEqual(products.map((p) => p.name), ['第三件', '第二件', '第一件']);
});
