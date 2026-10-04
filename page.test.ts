import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';

// 网页回归测试：启动真实服务和本机 Chrome（无头模式），通过 Chrome DevTools Protocol
// 驱动首页「新增商品」表单，验证用户在动态规格表单中填写、删除、提交、修正的完整过程。
// 不引入任何 npm 依赖：CDP 走 Node 内置的 WebSocket 客户端。
// 未安装 Chrome 时本文件中的测试自动跳过，接口回归测试（server.test.ts）不受影响。

const SERVER_PATH = join(import.meta.dirname, 'server.ts');

// ---------- 被测服务 ----------

interface RunningServer {
  url: string;
  dataDir: string;
  child: ChildProcess;
}

function startServer(): Promise<RunningServer> {
  const dataDir = mkdtempSync(join(tmpdir(), 'cartwell-page-test-'));
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

// ---------- Chrome 与 CDP ----------

function findChrome(): string | undefined {
  const candidates = [process.env.CHROME_BIN, 'google-chrome', 'chromium', 'chromium-browser']
    .filter((candidate): candidate is string => Boolean(candidate));
  for (const candidate of candidates) {
    const result = spawnSync(candidate, ['--version'], { stdio: 'pipe' });
    if (!result.error && result.status === 0) return candidate;
  }
  return undefined;
}

interface RunningChrome {
  child: ChildProcess;
  wsUrl: string;
  profileDir: string;
}

function startChrome(chromePath: string): Promise<RunningChrome> {
  const profileDir = mkdtempSync(join(tmpdir(), 'cartwell-chrome-'));
  const child = spawn(chromePath, [
    '--headless', '--disable-gpu', '--no-sandbox', '--disable-dev-shm-usage',
    '--remote-debugging-port=0', `--user-data-dir=${profileDir}`,
    '--no-first-run', '--no-default-browser-check', 'about:blank',
  ], { stdio: ['ignore', 'pipe', 'pipe'] });
  return new Promise((resolve, reject) => {
    let buffer = '';
    let settled = false;
    const fail = (error: Error): void => {
      if (!settled) { settled = true; reject(error); }
    };
    child.stderr!.setEncoding('utf8');
    child.stderr!.on('data', (chunk: string) => {
      buffer += chunk;
      const match = buffer.match(/DevTools listening on (ws:\/\/\S+)/);
      if (match && !settled) {
        settled = true;
        resolve({ child, wsUrl: match[1], profileDir });
      }
    });
    child.once('error', () => fail(new Error(`无法启动浏览器 ${chromePath}`)));
    child.once('exit', (code) => fail(new Error(`浏览器提前退出，退出码 ${code}`)));
  });
}

async function stopChrome(chrome: RunningChrome): Promise<void> {
  chrome.child.kill('SIGKILL');
  await Promise.race([
    once(chrome.child, 'exit'),
    new Promise((resolve) => setTimeout(resolve, 5000)),
  ]);
  rmSync(chrome.profileDir, { recursive: true, force: true });
}

// 最小 CDP 客户端：按 id 匹配响应，忽略事件通知。
class CdpConnection {
  private ws: WebSocket;
  private nextId = 0;
  private pending = new Map<number, { resolve: (value: any) => void; reject: (error: Error) => void }>();

  private constructor(ws: WebSocket) {
    this.ws = ws;
    ws.addEventListener('message', (event) => {
      const message = JSON.parse(String(event.data));
      if (typeof message.id !== 'number') return;
      const entry = this.pending.get(message.id);
      if (!entry) return;
      this.pending.delete(message.id);
      if (message.error) entry.reject(new Error(`${message.error.message}（CDP 错误 ${message.error.code}）`));
      else entry.resolve(message.result);
    });
    ws.addEventListener('close', () => {
      for (const entry of this.pending.values()) entry.reject(new Error('与浏览器的连接已断开'));
      this.pending.clear();
    });
  }

  static connect(wsUrl: string): Promise<CdpConnection> {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(wsUrl);
      const connection = new CdpConnection(ws);
      ws.addEventListener('open', () => resolve(connection), { once: true });
      ws.addEventListener('error', () => reject(new Error('无法连接浏览器调试接口')), { once: true });
    });
  }

  send(method: string, params: Record<string, unknown> = {}, sessionId?: string): Promise<any> {
    const id = ++this.nextId;
    const message: Record<string, unknown> = { id, method, params };
    if (sessionId) message.sessionId = sessionId;
    this.ws.send(JSON.stringify(message));
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`CDP 调用超时：${method}`));
      }, 30_000);
      this.pending.set(id, {
        resolve: (value) => { clearTimeout(timer); resolve(value); },
        reject: (error) => { clearTimeout(timer); reject(error); },
      });
    });
  }
}

// ---------- 测试夹具 ----------

interface Fixture {
  server: RunningServer;
  chrome: RunningChrome;
  cdp: CdpConnection;
  sessionId: string;
}

const fixture: Fixture = {} as Fixture;

// 在页面上下文中执行表达式并返回可 JSON 序列化的结果；页面脚本抛错时带上异常信息。
async function evalPage<T>(expression: string): Promise<T> {
  const result = await fixture.cdp.send('Runtime.evaluate', {
    expression,
    awaitPromise: true,
    returnByValue: true,
  }, fixture.sessionId);
  if (result.exceptionDetails) {
    const detail = result.exceptionDetails.exception?.description ?? result.exceptionDetails.text;
    throw new Error(`页面脚本执行失败：${detail}`);
  }
  return result.result.value as T;
}

async function waitFor(check: () => Promise<boolean>, description: string, timeoutMs = 15_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    let ok = false;
    try { ok = await check(); } catch { ok = false; } // 导航期间执行环境会短暂销毁，重试即可
    if (ok) return;
    if (Date.now() > deadline) throw new Error(`等待超时：${description}`);
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}

async function getProducts(url: string): Promise<any[]> {
  const response = await fetch(`${url}/api/products`);
  assert.equal(response.status, 200);
  const body = await response.json();
  return body.products;
}

const chromePath = findChrome();

describe('首页「新增商品」网页回归', () => {
  before(async () => {
    if (!chromePath) return;
    fixture.server = await startServer();
    // 预置一件已有商品：验证失败提交不影响列表，且新商品成功后排在它之前
    const existing = await fetch(`${fixture.server.url}/api/products`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        name: '已有商品',
        specs: [{ attributes: [{ name: '颜色', value: '黑色' }], price: '59.00', stock: 12 }],
      }),
    });
    assert.equal(existing.status, 201);

    fixture.chrome = await startChrome(chromePath);
    fixture.cdp = await CdpConnection.connect(fixture.chrome.wsUrl);
    const { targetId } = await fixture.cdp.send('Target.createTarget', { url: `${fixture.server.url}/` });
    const { sessionId } = await fixture.cdp.send('Target.attachToTarget', { targetId, flatten: true });
    fixture.sessionId = sessionId;
    await fixture.cdp.send('Runtime.enable', {}, sessionId);
    // createTarget 返回时导航可能尚未提交，此时上下文还是 about:blank（readyState 也是
    // complete），必须等到目标页面真正加载出表单再开始操作。
    await waitFor(
      async () => (await evalPage<string>(
        `document.readyState + '|' + Boolean(document.getElementById('product-form'))`,
      )) === 'complete|true',
      '首页加载完成',
    );
  });

  after(async () => {
    if (fixture.chrome) await stopChrome(fixture.chrome);
    if (fixture.server) await stopServer(fixture.server);
  });

  test('删除前面的规格和属性后，编号连续、提交内容与页面一致，字段错误定位到当前行且内容保留', async (t) => {
    if (!chromePath) { t.skip('未找到 Chrome，跳过网页回归测试'); return; }
    const { server } = fixture;

    // 在页面上填写：名称带首尾空白；三条规格，随后删除第一条规格和第二条规格中的第一个属性
    const filled = await evalPage<any>(`(() => {
      const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));
      const nameInput = document.getElementById('product-name');
      nameInput.value = '  回归测试商品  ';
      const cards = () => $$('#specs [data-spec]');
      const fillCard = (card, attrs, price, stock) => {
        while (card.querySelectorAll('.attr-row').length < attrs.length) {
          card.querySelector('.add-attr').click();
        }
        $$('.attr-row', card).forEach((row, index) => {
          row.querySelector('[data-attr-name]').value = attrs[index][0];
          row.querySelector('[data-attr-value]').value = attrs[index][1];
        });
        card.querySelector('[data-price]').value = price;
        card.querySelector('[data-stock]').value = stock;
      };
      // 规格 1：整条将被删除
      fillCard(cards()[0], [['颜色', '待删除色']], '1.00', '1');
      // 规格 2：第一个属性「材质」将被删除；售价 12.345 不合规，留待修正
      document.getElementById('add-spec').click();
      fillCard(cards()[1], [['材质', '棉'], ['颜色', '红色'], ['尺码', 'M']], '12.345', '7');
      // 规格 3：属性值只含空白，留待修正；库存为零
      document.getElementById('add-spec').click();
      fillCard(cards()[2], [['颜色', '   ']], '8.8', '0');
      // 删除规格 2 的第一个属性，再删除规格 1
      $$('.attr-row', cards()[1])[0].querySelector('.remove-attr').click();
      cards()[0].querySelector('.remove-spec').click();
      return {
        legends: cards().map((card) => card.querySelector('[data-spec-no]').textContent),
        name: nameInput.value,
        specs: cards().map((card) => ({
          attrs: $$('.attr-row', card).map((row) => [
            row.querySelector('[data-attr-name]').value,
            row.querySelector('[data-attr-value]').value,
          ]),
          price: card.querySelector('[data-price]').value,
          stock: card.querySelector('[data-stock]').value,
        })),
      };
    })()`);

    assert.deepEqual(filled.legends, ['规格 1', '规格 2'], '删除前面的规格后，剩余规格的显示编号应连续');
    assert.deepEqual(filled.specs, [
      { attrs: [['颜色', '红色'], ['尺码', 'M']], price: '12.345', stock: '7' },
      { attrs: [['颜色', '   ']], price: '8.8', stock: '0' },
    ], '删除后页面上的属性、售价和库存应与原填写行一一对应，不能串行');

    // 拦截 fetch 记录实际提交内容，然后提交表单
    const submitState = await evalPage<any>(`(() => {
      window.__captured = [];
      const originalFetch = window.fetch.bind(window);
      window.fetch = (url, options) => {
        window.__captured.push({ url: String(url), body: options && options.body });
        return originalFetch(url, options);
      };
      document.getElementById('product-form').requestSubmit();
      return { disabled: document.getElementById('submit-btn').disabled };
    })()`);
    assert.equal(submitState.disabled, true, '提交过程中按钮应暂时不可用');

    // 等待失败响应渲染完成
    await waitFor(async () => {
      const status = await evalPage<any>(`(() => {
        const box = document.getElementById('form-status');
        return { cls: box.className, disabled: document.getElementById('submit-btn').disabled };
      })()`);
      return status.cls === 'error';
    }, '失败提示出现');
    const afterFailure = await evalPage<any>(`(() => {
      const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));
      const cards = $$('#specs [data-spec]');
      return {
        disabled: document.getElementById('submit-btn').disabled,
        pathname: location.pathname,
        statusText: document.getElementById('form-status').textContent,
        captured: window.__captured,
        name: document.getElementById('product-name').value,
        nameErr: document.querySelector('[data-err="name"]').textContent,
        nameInvalid: document.getElementById('product-name').classList.contains('invalid'),
        specs: cards.map((card) => ({
          legend: card.querySelector('[data-spec-no]').textContent,
          attrs: $$('.attr-row', card).map((row) => ({
            name: row.querySelector('[data-attr-name]').value,
            value: row.querySelector('[data-attr-value]').value,
            nameErr: row.querySelector('[data-err="attrName"]').textContent,
            valueErr: row.querySelector('[data-err="attrValue"]').textContent,
            nameInvalid: row.querySelector('[data-attr-name]').classList.contains('invalid'),
            valueInvalid: row.querySelector('[data-attr-value]').classList.contains('invalid'),
          })),
          price: card.querySelector('[data-price]').value,
          priceErr: card.querySelector('[data-err="price"]').textContent,
          priceInvalid: card.querySelector('[data-price]').classList.contains('invalid'),
          stock: card.querySelector('[data-stock]').value,
          stockErr: card.querySelector('[data-err="stock"]').textContent,
          stockInvalid: card.querySelector('[data-stock]').classList.contains('invalid'),
        })),
      };
    })()`);

    assert.equal(afterFailure.disabled, false, '失败响应结束后按钮应恢复可用');
    assert.equal(afterFailure.pathname, '/', '失败时应停留在当前表单页面');
    assert.match(afterFailure.statusText, /未创建任何记录/, '页面应明确说明商品没有创建');
    assert.match(afterFailure.statusText, /已保留填写内容/, '页面应提示填写内容已保留');

    // 实际提交的内容与当前页面一致：被删除的规格和属性不能出现，其余不串行
    assert.equal(afterFailure.captured.length, 1, '只应提交一次');
    const payload = JSON.parse(afterFailure.captured[0].body);
    assert.equal(payload.name, '  回归测试商品  ', '商品名称应保留原输入（含首尾空白）');
    assert.equal(payload.specs.length, 2, '被删除的规格不能出现在提交内容中');
    assert.deepEqual(payload.specs[0], {
      attributes: [{ name: '颜色', value: '红色' }, { name: '尺码', value: 'M' }],
      price: '12.345',
      stock: 7,
    });
    assert.deepEqual(payload.specs[1], {
      attributes: [{ name: '颜色', value: '   ' }],
      price: '8.8',
      stock: 0,
    });
    assert.ok(!afterFailure.captured[0].body.includes('待删除色'), '被删除规格的内容不能被带上');
    assert.ok(!afterFailure.captured[0].body.includes('材质'), '被删除属性的内容不能被带上');

    // 错误定位到当前留下的规格和属性：规格 1 的售价、规格 2 第一项属性的值
    assert.deepEqual(afterFailure.specs.map((spec: any) => spec.legend), ['规格 1', '规格 2']);
    const [first, second] = afterFailure.specs;
    assert.match(first.priceErr, /售价/, '规格 1 的售价旁应显示原因');
    assert.equal(first.priceInvalid, true, '规格 1 的售价输入框应被标出');
    assert.equal(first.stockErr, '', '库存合法不应被标记');
    assert.equal(first.stockInvalid, false);
    assert.ok(first.attrs.every((attr: any) => attr.nameErr === '' && attr.valueErr === '' && !attr.nameInvalid && !attr.valueInvalid),
      '规格 1 的属性合法，不应被标记为同类错误');
    assert.match(second.attrs[0].valueErr, /属性值/, '规格 2 的属性值旁应显示原因');
    assert.equal(second.attrs[0].valueInvalid, true, '规格 2 的属性值输入框应被标出');
    assert.equal(second.attrs[0].nameErr, '', '属性名称合法不应被标记');
    assert.equal(second.attrs[0].nameInvalid, false);
    assert.equal(second.priceErr, '', '规格 2 的售价合法不应被标记');
    assert.equal(second.priceInvalid, false);
    assert.equal(afterFailure.nameErr, '', '商品名称合法不应被标记');
    assert.equal(afterFailure.nameInvalid, false);

    // 刚才输入的文字、金额、库存和当前行的顺序都留在表单中
    assert.equal(afterFailure.name, '  回归测试商品  ');
    assert.deepEqual(afterFailure.specs.map((spec: any) => ({
      attrs: spec.attrs.map((attr: any) => [attr.name, attr.value]),
      price: spec.price,
      stock: spec.stock,
    })), [
      { attrs: [['颜色', '红色'], ['尺码', 'M']], price: '12.345', stock: '7' },
      { attrs: [['颜色', '   ']], price: '8.8', stock: '0' },
    ], '失败后表单应保留全部输入和行顺序');

    // 列表里的已有商品及其规格保持不变
    const products = await getProducts(server.url);
    assert.equal(products.length, 1, '校验失败不能新增任何记录');
    assert.equal(products[0].name, '已有商品');
    assert.deepEqual(products[0].specs, [{
      attributes: [{ name: '颜色', value: '黑色' }],
      price: '59.00',
      stock: 12,
    }], '已有商品及其规格、售价和库存应保持不变');
  });

  test('修正两处错误后直接再次提交：旧错误被清除，成功后返回首页且新商品按修正后的内容展示', async (t) => {
    if (!chromePath) { t.skip('未找到 Chrome，跳过网页回归测试'); return; }
    const { server } = fixture;

    // 只改两处错误：售价改为一位小数（验证两位小数显示），空白属性值改为带首尾空白的文字（验证去空白展示）
    const resubmit = await evalPage<any>(`(() => {
      const cards = Array.from(document.querySelectorAll('#specs [data-spec]'));
      cards[0].querySelector('[data-price]').value = '12.3';
      cards[1].querySelector('[data-attr-value]').value = '  蓝色  ';
      document.getElementById('product-form').requestSubmit();
      return {
        disabled: document.getElementById('submit-btn').disabled,
        errTexts: Array.from(document.querySelectorAll('#product-form .err')).map((slot) => slot.textContent),
        invalidCount: document.querySelectorAll('#product-form .invalid').length,
        statusCls: document.getElementById('form-status').className,
        capturedCount: window.__captured.length,
        secondBody: window.__captured[1] && window.__captured[1].body,
      };
    })()`);

    assert.equal(resubmit.disabled, true, '再次提交过程中按钮应暂时不可用');
    assert.equal(resubmit.statusCls, '', '再次提交时顶部的失败提示应被清除');
    assert.ok(resubmit.errTexts.every((text: string) => text === ''), '再次提交时旧的错误文字应被清除');
    assert.equal(resubmit.invalidCount, 0, '再次提交时旧的输入框标记应被清除');
    assert.equal(resubmit.capturedCount, 2, '无须重新添加规格或重填名称，应直接再次提交');
    const secondPayload = JSON.parse(resubmit.secondBody);
    assert.equal(secondPayload.name, '  回归测试商品  ', '名称沿用原输入');
    assert.equal(secondPayload.specs.length, 2, '规格数量不变');
    assert.deepEqual(secondPayload.specs[0].attributes, [
      { name: '颜色', value: '红色' }, { name: '尺码', value: 'M' },
    ]);
    assert.equal(secondPayload.specs[0].price, '12.3');
    assert.equal(secondPayload.specs[0].stock, 7);
    assert.deepEqual(secondPayload.specs[1].attributes, [{ name: '颜色', value: '  蓝色  ' }]);
    assert.equal(secondPayload.specs[1].price, '8.8');
    assert.equal(secondPayload.specs[1].stock, 0, '库存为零的规格应照常提交');

    // 等待创建成功（以接口为准），随后页面应自行返回首页
    await waitFor(async () => (await getProducts(server.url)).length === 2, '商品创建成功');
    await waitFor(async () => {
      const state = await evalPage<any>(`({
        ready: document.readyState,
        pathname: location.pathname,
        capturedGone: typeof window.__captured === 'undefined',
        hasList: Boolean(document.getElementById('product-list')),
      })`);
      return state.ready === 'complete' && state.pathname === '/' && state.capturedGone && state.hasList;
    }, '成功后返回首页');

    // 接口侧：新商品排在最前，名称为去空白后的内容，金额两位小数，零库存规格保留
    const products = await getProducts(server.url);
    assert.equal(products.length, 2);
    assert.equal(products[0].name, '回归测试商品', '名称按去除首尾空白后的内容保存');
    assert.equal(products[1].name, '已有商品', '已有商品保持原样且排在其后');
    assert.deepEqual(products[0].specs, [
      {
        attributes: [{ name: '颜色', value: '红色' }, { name: '尺码', value: 'M' }],
        price: '12.30',
        stock: 7,
      },
      {
        attributes: [{ name: '颜色', value: '蓝色' }],
        price: '8.80',
        stock: 0,
      },
    ], '保存的是这次修正后保留的规格，属性值去空白，金额两位小数，零库存不被丢弃');

    // 首页展示与之一致
    const listed = await evalPage<any>(`(() => {
      const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));
      return $$('#product-list .product').map((product) => ({
        name: product.querySelector('h3').textContent,
        specs: $$('.spec-row', product).map((row) => ({
          attrs: $$('.attr', row).map((attr) => attr.textContent),
          price: row.querySelector('.price').textContent,
          stock: row.querySelector('.stock').textContent,
          outOfStock: Boolean(row.querySelector('.badge-oos')),
        })),
      }));
    })()`);
    assert.equal(listed.length, 2);
    assert.equal(listed[0].name, '回归测试商品', '新增商品应排在已有商品之前');
    assert.deepEqual(listed[0].specs, [
      {
        attrs: ['颜色：红色', '尺码：M'],
        price: '¥12.30',
        stock: '库存 7',
        outOfStock: false,
      },
      {
        attrs: ['颜色：蓝色'],
        price: '¥8.80',
        stock: '库存 0',
        outOfStock: true,
      },
    ], '首页展示修正后保留的规格：售价两位小数、属性去空白、零库存规格显示「缺货」');
    assert.equal(listed[1].name, '已有商品');
    assert.deepEqual(listed[1].specs, [{
      attrs: ['颜色：黑色'],
      price: '¥59.00',
      stock: '库存 12',
      outOfStock: false,
    }], '已有商品的展示保持不变');
  });
});
