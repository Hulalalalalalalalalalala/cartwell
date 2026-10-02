import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';

const PRODUCT: string = 'Cartwell';
const RESOURCE: string = 'products';
const MAX_BODY_BYTES: number = 1_048_576;

// ---------- 数据模型 ----------

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
type FieldName = 'name' | 'spec' | 'attributes' | 'attrName' | 'attrValue' | 'price' | 'stock';
interface FieldError {
  path: string;
  field: FieldName;
  message: string;
  specIndex?: number;
  attributeIndex?: number;
}
type ValidationResult =
  | { ok: true; name: string; specs: Spec[] }
  | { ok: false; errors: FieldError[] };

const PRICE_PATTERN = /^\d+(?:\.\d{1,2})?$/;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

// 金额字符串规范化：只接受零或最多两位小数的十进制写法，按字符串运算避免精度丢失。
function normalizePrice(raw: unknown): { ok: true; price: string } | { ok: false } {
  if (typeof raw !== 'string' || !PRICE_PATTERN.test(raw)) return { ok: false };
  const [wholeRaw, fractionRaw] = raw.split('.');
  const whole = wholeRaw.replace(/^0+(?=\d)/, '');
  const fraction = (fractionRaw ?? '').padEnd(2, '0');
  return { ok: true, price: `${whole}.${fraction}` };
}

function validateStock(raw: unknown): number | undefined {
  if (typeof raw !== 'number' || !Number.isInteger(raw)) return undefined;
  if (raw < 0 || !Number.isSafeInteger(raw)) return undefined;
  return raw;
}

// 规格的顺序无关签名：属性编码为 JSON 后排序连接，无碰撞风险；大小写敏感。
function specSignature(attributes: Attribute[]): string {
  return attributes
    .map((attribute) => JSON.stringify([attribute.name, attribute.value]))
    .sort()
    .join('\u0000');
}

// 按与网页表单一致的规则校验并规范化整个商品，返回所有需要修正的字段。
function validateProduct(input: unknown): ValidationResult {
  const errors: FieldError[] = [];

  if (!isPlainObject(input)) {
    return { ok: false, errors: [{ path: '', field: 'spec', message: '请求体必须是一个商品对象' }] };
  }

  let name = '';
  if (typeof input.name !== 'string') {
    errors.push({ path: 'name', field: 'name', message: '商品名称必须是文字' });
  } else {
    name = input.name.trim();
    if (name === '') errors.push({ path: 'name', field: 'name', message: '商品名称不能为空' });
  }

  if (!Array.isArray(input.specs)) {
    errors.push({ path: 'specs', field: 'spec', message: '规格必须是数组，且至少包含一条规格' });
    return { ok: false, errors };
  }
  if (input.specs.length === 0) {
    errors.push({ path: 'specs', field: 'spec', message: '至少需要一条规格' });
    return { ok: false, errors };
  }

  const normalizedSpecs: Spec[] = [];
  const specSignatures = new Map<string, number>();
  const flaggedSpecs = new Set<number>();

  input.specs.forEach((rawSpec, specIndex) => {
    const basePath = `specs[${specIndex}]`;
    const specValid: Spec = { attributes: [], price: '', stock: 0 };
    let specOk = true;

    if (!isPlainObject(rawSpec)) {
      errors.push({ path: basePath, field: 'spec', specIndex, message: '该规格格式不正确' });
      return;
    }

    if (!Array.isArray(rawSpec.attributes) || rawSpec.attributes.length === 0) {
      errors.push({
        path: `${basePath}.attributes`, field: 'attributes', specIndex,
        message: '该规格至少需要一个属性',
      });
      specOk = false;
    } else {
      const seenNames = new Set<string>();
      rawSpec.attributes.forEach((rawAttribute, attributeIndex) => {
        const attrPath = `${basePath}.attributes[${attributeIndex}]`;
        if (!isPlainObject(rawAttribute)) {
          errors.push({
            path: attrPath, field: 'attrName', specIndex, attributeIndex,
            message: '该属性格式不正确',
          });
          specOk = false;
          return;
        }
        let attributeName: string;
        let attributeValue: string;
        if (typeof rawAttribute.name !== 'string') {
          errors.push({
            path: `${attrPath}.name`, field: 'attrName', specIndex, attributeIndex,
            message: '属性名称必须是文字',
          });
          specOk = false;
          return;
        }
        attributeName = rawAttribute.name.trim();
        if (attributeName === '') {
          errors.push({
            path: `${attrPath}.name`, field: 'attrName', specIndex, attributeIndex,
            message: '属性名称不能为空',
          });
          specOk = false;
          return;
        }
        if (typeof rawAttribute.value !== 'string') {
          errors.push({
            path: `${attrPath}.value`, field: 'attrValue', specIndex, attributeIndex,
            message: '属性值必须是文字',
          });
          specOk = false;
          return;
        }
        attributeValue = rawAttribute.value.trim();
        if (attributeValue === '') {
          errors.push({
            path: `${attrPath}.value`, field: 'attrValue', specIndex, attributeIndex,
            message: '属性值不能为空',
          });
          specOk = false;
          return;
        }
        if (seenNames.has(attributeName)) {
          errors.push({
            path: `${attrPath}.name`, field: 'attrName', specIndex, attributeIndex,
            message: `属性名称「${attributeName}」在同一规格内重复`,
          });
          specOk = false;
          return;
        }
        seenNames.add(attributeName);
        specValid.attributes.push({ name: attributeName, value: attributeValue });
      });
    }

    const priceResult = normalizePrice(rawSpec.price);
    if (!priceResult.ok) {
      errors.push({
        path: `${basePath}.price`, field: 'price', specIndex,
        message: '售价必须是十进制金额字符串：允许零和最多两位小数，不接受负数、指数写法、千位分隔符或更多位小数',
      });
      specOk = false;
    } else {
      specValid.price = priceResult.price;
    }

    const stock = validateStock(rawSpec.stock);
    if (stock === undefined) {
      errors.push({
        path: `${basePath}.stock`, field: 'stock', specIndex,
        message: '库存必须是非负安全整数，不能留空或使用小数',
      });
      specOk = false;
    } else {
      specValid.stock = stock;
    }

    if (specOk) {
      const signature = specSignature(specValid.attributes);
      const firstIndex = specSignatures.get(signature);
      if (firstIndex === undefined) {
        specSignatures.set(signature, specIndex);
      } else {
        if (!flaggedSpecs.has(firstIndex)) {
          errors.push({
            path: `specs[${firstIndex}]`, field: 'spec', specIndex: firstIndex,
            message: `与第 ${specIndex + 1} 条规格的属性名称和值完全相同`,
          });
          flaggedSpecs.add(firstIndex);
        }
        errors.push({
          path: basePath, field: 'spec', specIndex,
          message: `与第 ${firstIndex + 1} 条规格的属性名称和值完全相同（调换属性顺序也算重复）`,
        });
        flaggedSpecs.add(specIndex);
      }
    }
    normalizedSpecs.push(specValid);
  });

  if (errors.length > 0) return { ok: false, errors };
  return { ok: true, name, specs: normalizedSpecs };
}

// ---------- 持久化 ----------

const args: string[] = process.argv.slice(2);
const help: string = `Cartwell - 商品目录与购物订单
Usage: node server.ts serve [--host ADDRESS] [--port PORT] [--data-dir DIRECTORY]
       node server.ts --help
Defaults: --host 127.0.0.1 --port 8080 --data-dir data
Port 0 selects an available port.
`;
if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
  process.stdout.write(help);
  process.exit(args.length === 0 ? 2 : 0);
}
if (args.shift() !== 'serve') { console.error('Expected serve or --help'); process.exit(2); }
let host: string = '127.0.0.1';
let port: number = 8080;
let dataDir: string = 'data';
while (args.length) {
  const flag = args.shift();
  const value = args.shift();
  if (!value || !['--host', '--port', '--data-dir'].includes(flag ?? '')) {
    console.error('Each option must be --host, --port or --data-dir followed by a value'); process.exit(2);
  }
  if (flag === '--host') host = value;
  else if (flag === '--port') {
    if (!/^\d+$/.test(value) || Number(value) > 65535) { console.error('Port must be between 0 and 65535'); process.exit(2); }
    port = Number(value);
  } else dataDir = value;
}

mkdirSync(dataDir, { recursive: true });
const dataFile = join(dataDir, 'products.json');
const tempFile = join(dataDir, 'products.json.tmp');
try { writeFileSync(dataFile, '[]\n', { flag: 'wx' }); } catch (error) {
  if (!(error instanceof Error && 'code' in error && error.code === 'EEXIST')) throw error;
}

function readProducts(): Product[] {
  const records: unknown = JSON.parse(readFileSync(dataFile, 'utf8'));
  if (!Array.isArray(records)) throw new Error('Invalid record list');
  return records as Product[];
}

// 先写临时文件再重命名：写盘失败时旧数据保持完好，不会出现部分保存。
function saveProducts(products: Product[]): void {
  writeFileSync(tempFile, `${JSON.stringify(products, null, 2)}\n`);
  renameSync(tempFile, dataFile);
}

// ---------- 网页 ----------

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderProductList(products: Product[]): string {
  if (products.length === 0) {
    return '<p id="empty-tip" class="empty">还没有商品记录。使用下方「新增商品」表单创建第一条记录。</p>';
  }
  const items = products.map((product) => {
    const specs = product.specs.map((spec) => {
      const attributes = spec.attributes
        .map((attribute) => `<span class="attr">${escapeHtml(attribute.name)}：${escapeHtml(attribute.value)}</span>`)
        .join('<span class="attr-sep">，</span>');
      const outOfStock = spec.stock === 0 ? '<span class="badge badge-oos">缺货</span>' : '';
      return `<li class="spec-row"><span class="attrs">${attributes}</span>`
        + `<span class="price">¥${escapeHtml(spec.price)}</span>`
        + `<span class="stock">库存 ${spec.stock}</span>${outOfStock}</li>`;
    }).join('');
    return `<li class="product"><h3>${escapeHtml(product.name)}</h3><ul class="specs">${specs}</ul></li>`;
  }).join('');
  return `<ul id="product-list" class="product-list">${items}</ul>`;
}

const PAGE_STYLE = `
:root{color-scheme:light}
*{box-sizing:border-box}
body{font-family:system-ui,sans-serif;max-width:52rem;margin:3rem auto;padding:0 1rem;line-height:1.7;color:#1f2430}
a{color:#175b9c}
h1{margin-bottom:0}
h2{margin-top:2.5rem;border-bottom:1px solid #d9dee8;padding-bottom:.3rem}
h3{margin:.4rem 0}
.empty{color:#6b7280;background:#f4f6fa;border:1px dashed #c6cedb;padding:.8rem 1rem;border-radius:.5rem}
.product-list{list-style:none;padding:0}
.product{border:1px solid #d9dee8;border-radius:.6rem;padding:.6rem 1rem;margin:1rem 0;background:#fff}
.specs{list-style:none;padding:0;margin:.4rem 0}
.spec-row{display:flex;flex-wrap:wrap;gap:.4rem .8rem;align-items:center;padding:.35rem 0;border-top:1px dashed #e5e8ef;font-size:.95rem}
.attr{color:#374151}
.price{font-variant-numeric:tabular-nums;color:#0f5132;font-weight:600}
.stock{color:#4b5563;font-variant-numeric:tabular-nums}
.badge{font-size:.8rem;padding:.05rem .5rem;border-radius:999px}
.badge-oos{background:#fde8e8;color:#b4231a;border:1px solid #f3b6b1}
form#product-form{border:1px solid #d9dee8;border-radius:.6rem;padding:1rem 1.2rem;background:#fbfcfe}
.spec{border:1px solid #d3dae6;border-radius:.5rem;padding:.6rem .9rem;margin:.8rem 0;background:#fff}
.attr-row{display:flex;flex-wrap:wrap;gap:.5rem;align-items:center;margin:.4rem 0}
.attr-row input{max-width:12rem}
input[type=text]{padding:.35rem .5rem;border:1px solid #b9c2d1;border-radius:.35rem;font:inherit}
input.invalid{border-color:#c02b1f;box-shadow:0 0 0 2px #f8d5d0}
button{font:inherit;padding:.35rem .8rem;border-radius:.35rem;border:1px solid #9aa7bb;background:#f3f6fb;cursor:pointer}
button.primary{background:#175b9c;color:#fff;border-color:#175b9c;font-weight:600}
button:disabled{opacity:.6;cursor:wait}
.err{color:#b4231a;font-size:.85rem;min-height:1em}
#form-status{margin:.8rem 0;padding:.6rem .9rem;border-radius:.5rem;display:none}
#form-status.error{display:block;background:#fde8e8;border:1px solid #f3b6b1;color:#8a1c14}
.field label{display:flex;gap:.5rem;align-items:center;flex-wrap:wrap}
.form-actions{margin-top:.8rem;display:flex;gap:.8rem;align-items:center}
`;

const PAGE_SCRIPT = `
(function () {
  var form = document.getElementById('product-form');
  var nameInput = document.getElementById('product-name');
  var specsBox = document.getElementById('specs');
  var statusBox = document.getElementById('form-status');
  var submitBtn = document.getElementById('submit-btn');

  function attrRowHtml() {
    return '<div class="attr-row">'
      + '<input type="text" data-attr-name placeholder="属性名称，如：颜色" maxlength="100">'
      + '<input type="text" data-attr-value placeholder="属性值，如：红色" maxlength="200">'
      + '<button type="button" class="remove-attr">删除属性</button>'
      + '<span class="err" data-err="attrName"></span>'
      + '<span class="err" data-err="attrValue"></span>'
      + '</div>';
  }
  function specCardHtml() {
    return '<fieldset class="spec" data-spec>'
      + '<legend data-spec-no>规格 1</legend>'
      + '<div class="attrs" data-attrs>' + attrRowHtml() + '</div>'
      + '<p><button type="button" class="add-attr">添加属性</button> '
      + '<button type="button" class="remove-spec">删除此规格</button></p>'
      + '<p class="field"><label>售价 <input type="text" inputmode="decimal" data-price placeholder="如 10.00"></label>'
      + '<span class="err" data-err="price"></span></p>'
      + '<p class="field"><label>库存 <input type="text" inputmode="numeric" data-stock placeholder="非负整数"></label>'
      + '<span class="err" data-err="stock"></span></p>'
      + '<p class="err" data-err="spec"></p>'
      + '<p class="err" data-err="attributes"></p>'
      + '</fieldset>';
  }
  function refreshNumbers() {
    var cards = specsBox.querySelectorAll('[data-spec]');
    for (var i = 0; i < cards.length; i++) {
      cards[i].querySelector('[data-spec-no]').textContent = '规格 ' + (i + 1);
    }
  }
  function addSpec() {
    specsBox.insertAdjacentHTML('beforeend', specCardHtml());
    refreshNumbers();
  }
  specsBox.addEventListener('click', function (event) {
    var target = event.target;
    if (!(target instanceof Element)) return;
    if (target.classList.contains('add-attr')) {
      var card = target.closest('[data-spec]');
      card.querySelector('[data-attrs]').insertAdjacentHTML('beforeend', attrRowHtml());
    } else if (target.classList.contains('remove-attr')) {
      var row = target.closest('.attr-row');
      if (row.parentElement.querySelectorAll('.attr-row').length > 1) row.remove();
    } else if (target.classList.contains('remove-spec')) {
      if (specsBox.querySelectorAll('[data-spec]').length > 1) {
        target.closest('[data-spec]').remove();
        refreshNumbers();
      }
    }
  });
  document.getElementById('add-spec').addEventListener('click', addSpec);

  function clearErrors() {
    statusBox.className = '';
    statusBox.textContent = '';
    var slots = form.querySelectorAll('.err');
    for (var i = 0; i < slots.length; i++) slots[i].textContent = '';
    var invalids = form.querySelectorAll('.invalid');
    for (var j = 0; j < invalids.length; j++) invalids[j].classList.remove('invalid');
  }
  function setSlotError(container, key, text, inputKey) {
    var slot = container.querySelector('[data-err="' + key + '"]');
    if (slot) slot.textContent = text;
    if (inputKey) {
      var input = container.querySelector('[' + inputKey + ']');
      if (input) input.classList.add('invalid');
    }
  }
  function showFailure(message, details) {
    statusBox.className = 'error';
    statusBox.textContent = message + '（已保留填写内容，修正后可再次提交）';
    if (!details) return;
    details.forEach(function (detail) {
      if (detail.field === 'name') {
        setSlotError(form, 'name', detail.message, 'data-name-input');
        return;
      }
      var cards = specsBox.querySelectorAll('[data-spec]');
      var card = cards[detail.specIndex];
      if (!card) return;
      if (detail.field === 'attrName' || detail.field === 'attrValue') {
        var rows = card.querySelectorAll('.attr-row');
        var row = rows[detail.attributeIndex];
        if (row) {
          var key = detail.field === 'attrName' ? 'attrName' : 'attrValue';
          var inputKey = detail.field === 'attrName' ? 'data-attr-name' : 'data-attr-value';
          setSlotError(row, key, detail.message, inputKey);
        }
        return;
      }
      var inputKey = detail.field === 'price' ? 'data-price' : detail.field === 'stock' ? 'data-stock' : null;
      setSlotError(card, detail.field, detail.message, inputKey);
    });
  }
  function showSaveError() {
    statusBox.className = 'error';
    statusBox.textContent = '保存失败，商品未保存，请稍后重试。已有商品没有受到影响，填写内容仍然保留。';
  }

  function collectPayload() {
    var payload = { name: nameInput.value, specs: [] };
    var cards = specsBox.querySelectorAll('[data-spec]');
    for (var i = 0; i < cards.length; i++) {
      var card = cards[i];
      var attributes = [];
      var rows = card.querySelectorAll('.attr-row');
      for (var j = 0; j < rows.length; j++) {
        attributes.push({
          name: rows[j].querySelector('[data-attr-name]').value,
          value: rows[j].querySelector('[data-attr-value]').value
        });
      }
      var stockRaw = card.querySelector('[data-stock]').value;
      var stock;
      if (stockRaw === '') {
        stock = null;
      } else if (/^\\d+$/.test(stockRaw) && Number(stockRaw) <= Number.MAX_SAFE_INTEGER) {
        stock = Number(stockRaw);
      } else {
        stock = stockRaw;
      }
      payload.specs.push({
        attributes: attributes,
        price: card.querySelector('[data-price]').value,
        stock: stock
      });
    }
    return payload;
  }

  addSpec();
  form.addEventListener('submit', function (event) {
    event.preventDefault();
    clearErrors();
    submitBtn.disabled = true;
    fetch('/api/products', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(collectPayload())
    }).then(function (response) {
      return response.json().catch(function () { return null; }).then(function (data) {
        return { status: response.status, data: data };
      });
    }).then(function (result) {
      submitBtn.disabled = false;
      if (result.status === 201 && result.data) {
        window.location.assign('/');
        return;
      }
      if (result.status === 400 && result.data) {
        showFailure(result.data.error || '提交内容不符合要求', result.data.details);
      } else {
        showSaveError();
      }
    }).catch(function () {
      submitBtn.disabled = false;
      showSaveError();
    });
  });
})();
`;

function renderPage(products: Product[]): string {
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cartwell · 商品目录与购物订单</title>
<style>${PAGE_STYLE}</style>
</head>
<body>
<main>
<h1>Cartwell</h1>
<p>商品目录与购物订单</p>
<section>
<h2>商品列表</h2>
${renderProductList(products)}
</section>
<section>
<h2>新增商品</h2>
<form id="product-form" novalidate>
<p class="field"><label>商品名称 <input type="text" id="product-name" data-name-input maxlength="200" placeholder="输入商品名称"></label>
<span class="err" data-err="name"></span></p>
<div id="specs"></div>
<p><button type="button" id="add-spec">添加规格</button></p>
<div id="form-status" role="alert"></div>
<div class="form-actions"><button type="submit" class="primary" id="submit-btn">提交商品</button></div>
</form>
</section>
<p><a href="/api/products">查看商品列表接口</a> · <a href="/health">服务状态</a></p>
</main>
<script>${PAGE_SCRIPT}</script>
</body>
</html>`;
}

const ERROR_PAGE = (message: string): string => `<!doctype html>
<html lang="zh-CN"><meta charset="utf-8"><title>Cartwell · 出错了</title>
<body style="font-family:system-ui,sans-serif;max-width:40rem;margin:3rem auto;padding:0 1rem">
<h1>暂时无法读取商品</h1><p>${escapeHtml(message)}</p><p><a href="/">返回首页重试</a></p></body></html>`;

// ---------- HTTP 服务 ----------

function respond(res: ServerResponse, status: number, value: unknown, html = false, allow?: string): void {
  const body = html ? String(value) : JSON.stringify(value);
  const headers: Record<string, string> = {
    'content-type': html ? 'text/html; charset=utf-8' : 'application/json; charset=utf-8',
    'content-length': String(Buffer.byteLength(body)),
  };
  if (status === 405 && allow) headers.allow = allow;
  res.writeHead(status, headers);
  res.end(body);
}

function readJsonBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(new Error('invalid JSON'));
      }
    });
    req.on('error', () => reject(new Error('invalid JSON')));
  });
}

const ALLOWED_METHODS: Record<string, string[]> = {
  '/': ['GET'],
  '/health': ['GET'],
  '/api/products': ['GET', 'POST'],
};

const server = createServer((req: IncomingMessage, res: ServerResponse): void => {
  let route: string;
  try { route = new URL(req.url ?? '/', 'http://localhost').pathname; } catch { respond(res, 400, { error: 'invalid request path' }); return; }

  const allowed = ALLOWED_METHODS[route];
  if (!allowed) { respond(res, 404, { error: 'not found' }); return; }
  const method = req.method ?? '';
  if (!allowed.includes(method)) {
    respond(res, 405, { error: 'method not allowed', allowed }, false, allowed.join(', '));
    return;
  }

  if (route === '/health') { respond(res, 200, { status: 'ok', product: PRODUCT }); return; }

  if (route === '/' && method === 'GET') {
    try {
      respond(res, 200, renderPage(readProducts()), true);
    } catch {
      respond(res, 500, ERROR_PAGE('商品数据暂时无法读取，已有记录未被修改。'), true);
    }
    return;
  }

  if (route === '/api/products' && method === 'GET') {
    try {
      respond(res, 200, { [RESOURCE]: readProducts() });
    } catch {
      respond(res, 500, { error: 'unable to read products' });
    }
    return;
  }

  // POST /api/products
  readJsonBody(req).then((input) => {
    const result = validateProduct(input);
    if (!result.ok) {
      respond(res, 400, { error: '商品校验未通过，未创建任何记录', details: result.errors });
      return;
    }
    const product: Product = {
      id: randomUUID(),
      name: result.name,
      specs: result.specs,
      createdAt: new Date().toISOString(),
    };
    try {
      const products = readProducts();
      products.unshift(product); // 新创建的商品排在最前
      saveProducts(products);
    } catch {
      respond(res, 500, { error: '商品保存失败，请稍后重试；已有商品未受影响' });
      return;
    }
    respond(res, 201, product);
  }).catch((error: Error) => {
    if (error.message === 'request body too large') {
      respond(res, 400, { error: '请求体超过大小限制' });
    } else {
      respond(res, 400, { error: '请求内容不是合法的 JSON' });
    }
  });
});

server.once('error', (error: Error): void => { console.error(error.message); process.exitCode = 1; });
server.listen(port, host, (): void => {
  const address = server.address();
  if (address && typeof address !== 'string') {
    const displayedHost = address.address.includes(':') ? `[${address.address}]` : address.address;
    console.log(`${PRODUCT} listening on http://${displayedHost}:${address.port}`);
  }
});
for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, (): void => { server.close(() => { process.exitCode = 0; }); server.closeIdleConnections(); });
}
