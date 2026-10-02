import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { mkdirSync, readFileSync, writeFileSync, renameSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';

const PRODUCT: string = 'Cartwell';
const RESOURCE: string = 'products';

interface AttributeRecord { name: string; value: string; }
interface SpecRecord { attributes: AttributeRecord[]; price: string; stock: number; }
interface ProductRecord { id: string; name: string; specs: SpecRecord[]; }

interface FieldError {
  scope: 'product' | 'spec';
  spec?: number;
  field: string;
  attribute?: number;
  subfield?: string;
  message: string;
}

const PAGE: string = `<!doctype html>
<html lang="zh-CN">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cartwell · 商品目录与购物订单</title>
<style>
body{font-family:system-ui,sans-serif;max-width:52rem;margin:3rem auto;padding:0 1rem;line-height:1.7;color:#222}
a{color:#175b9c}
h1{margin-bottom:.25rem}
h2{margin:1.2rem 0 .4rem}
.subtitle{color:#666;margin-top:0}
.muted{color:#888;font-size:.85rem}
.toolbar{margin:.8rem 0;display:flex;gap:.5rem;align-items:center;flex-wrap:wrap}
button{font:inherit;cursor:pointer;border:1px solid #175b9c;background:#175b9c;color:#fff;padding:.4rem .9rem;border-radius:.3rem}
button.secondary{background:#fff;color:#175b9c}
button.danger{background:#fff;color:#b00020;border-color:#b00020;padding:.2rem .6rem;font-size:.85rem}
.product{border:1px solid #ddd;border-radius:.4rem;padding:.8rem 1rem;margin:.8rem 0;background:#fff}
.product h3{margin:.2rem 0 .5rem}
table.specs{width:100%;border-collapse:collapse;font-size:.95rem}
table.specs th,table.specs td{border:1px solid #e0e0e0;padding:.35rem .5rem;text-align:left;vertical-align:top}
table.specs th{background:#f7f7f7;font-weight:600}
.badge{display:inline-block;font-size:.75rem;padding:.05rem .45rem;border-radius:.8rem;background:#eee;color:#555;white-space:nowrap}
.badge.oos{background:#fdecea;color:#b00020}
.empty{border:1px dashed #bbb;border-radius:.4rem;padding:1.4rem;text-align:center;color:#666;background:#fafafa}
.spec-card{border:1px solid #ddd;border-radius:.4rem;padding:.7rem .9rem;margin:.7rem 0;background:#fff}
.spec-card h4{margin:.2rem 0 .5rem;display:flex;justify-content:space-between;align-items:center;gap:.5rem}
.attr-row{display:flex;gap:.4rem;margin:.3rem 0;align-items:center;flex-wrap:wrap}
.attr-row input{flex:1;min-width:8rem}
.field{margin:.5rem 0}
.field label{display:block;font-size:.85rem;color:#555;margin-bottom:.15rem}
input[type=text]{font:inherit;padding:.35rem .5rem;border:1px solid #bbb;border-radius:.3rem;width:100%;box-sizing:border-box}
input.invalid{border-color:#b00020;background:#fff5f5}
.field-error{color:#b00020;font-size:.82rem;margin:.15rem 0 0;min-height:1em}
.error-box{background:#fdecea;border:1px solid #f5c6c0;color:#b00020;border-radius:.4rem;padding:.6rem .9rem;margin:.7rem 0}
.success-box{background:#e8f5e9;border:1px solid #c8e6c9;color:#2e7d32;border-radius:.4rem;padding:.6rem .9rem;margin:.7rem 0}
</style>
<main>
<h1>Cartwell</h1>
<p class="subtitle">商品目录与购物订单</p>
<div id="view"><p class="muted">加载中…</p></div>
<p class="muted"><a href="/api/products">查看商品列表接口</a> · <a href="/health">服务状态</a></p>
</main>
<script>
"use strict";
var view = document.getElementById('view');
var products = [];
var formState = null;
var formErrors = [];
var justSaved = false;

function esc(s){
  var A = String.fromCharCode(38); // 与号，避免实体字面量在源码中被解码
  var ent = {'&': A+'amp;', '<': A+'lt;', '>': A+'gt;', '"': A+'quot;', "'": A+'#39;'};
  return String(s).replace(/[&<>"']/g, function(c){ return ent[c]; });
}

function loadProducts(){
  return fetch('/api/products').then(function(r){ return r.json(); }).then(function(data){
    products = (data && Array.isArray(data.products)) ? data.products : [];
    renderList();
  }).catch(function(){
    view.innerHTML = '<div class="error-box">商品列表加载失败，请刷新重试。</div>';
  });
}

function renderList(){
  var html = '';
  if(!products.length){
    html += '<div class="empty">还没有商品记录。点击「新增商品」开始添加。</div>';
  } else {
    html += '<div class="toolbar"><button type="button" id="addBtn">新增商品</button></div>';
    html += products.map(function(p){
      var rows = p.specs.map(function(s){
        var attrs = s.attributes.map(function(a){
          return esc(a.name) + '：' + esc(a.value);
        }).join('，');
        var oos = s.stock === 0;
        var stockCell = esc(s.stock) + (oos ? ' <span class="badge oos">缺货</span>' : '');
        return '<tr><td>' + attrs + '</td><td>' + esc(s.price) + '</td><td>' + stockCell + '</td></tr>';
      }).join('');
      return '<div class="product"><h3>' + esc(p.name) + '</h3>'
        + '<table class="specs"><thead><tr><th>规格属性</th><th>售价</th><th>库存</th></tr></thead>'
        + '<tbody>' + rows + '</tbody></table></div>';
    }).join('');
  }
  view.innerHTML = html;
  var btn = document.getElementById('addBtn');
  if(btn) btn.addEventListener('click', startAdd);
  if(justSaved){
    var last = view.querySelector('.product:last-child');
    if(last) last.scrollIntoView({block:'start'});
    justSaved = false;
  }
}

function startAdd(){
  formState = { name:'', specs:[{attributes:[{name:'',value:''}], price:'', stock:''}] };
  formErrors = [];
  renderForm();
}

function backToList(){
  formState = null;
  formErrors = [];
  renderList();
}

function renderForm(){
  var html = '';
  html += '<div class="toolbar"><button type="button" class="secondary" id="backBtn">返回列表</button></div>';
  html += '<h2>新增商品</h2>';
  html += '<div id="formNotice"></div>';
  html += '<form id="productForm" novalidate>';
  html += '<div class="field"><label for="fName">商品名称</label>';
  html += '<input type="text" id="fName" autocomplete="off" value="' + esc(formState.name) + '">';
  html += '<div class="field-error" data-err="product:name"></div></div>';
  html += '<div id="specs"></div>';
  html += '<div class="toolbar"><button type="button" class="secondary" id="addSpecBtn">添加规格</button></div>';
  html += '<div class="toolbar"><button type="submit">保存商品</button>';
  html += '<button type="button" class="secondary" id="cancelBtn">取消</button></div>';
  html += '</form>';
  view.innerHTML = html;
  renderSpecs();
  renderErrors();
  document.getElementById('backBtn').addEventListener('click', backToList);
  document.getElementById('cancelBtn').addEventListener('click', backToList);
  document.getElementById('addSpecBtn').addEventListener('click', function(){
    formState.specs.push({attributes:[{name:'',value:''}], price:'', stock:''});
    renderSpecs();
    renderErrors();
  });
  document.getElementById('productForm').addEventListener('submit', submitForm);
  document.getElementById('fName').addEventListener('input', function(){ formState.name = this.value; });
}

function renderSpecs(){
  var container = document.getElementById('specs');
  if(!container) return;
  container.innerHTML = formState.specs.map(function(s, i){
    var n = i + 1;
    var attrRows = s.attributes.map(function(a, j){
      var an = j + 1;
      var removeAttr = s.attributes.length > 1
        ? '<button type="button" class="danger" data-remove-attr="' + n + ':' + an + '">删除</button>' : '';
      return '<div class="attr-row">'
        + '<input type="text" placeholder="属性名称，如 颜色" data-spec="' + n + '" data-attr="' + an + '" data-sub="name" value="' + esc(a.name) + '">'
        + '<input type="text" placeholder="属性值，如 红色" data-spec="' + n + '" data-attr="' + an + '" data-sub="value" value="' + esc(a.value) + '">'
        + removeAttr + '</div>';
    }).join('');
    var removeSpec = formState.specs.length > 1
      ? '<button type="button" class="danger" data-remove-spec="' + n + '">删除规格</button>' : '';
    return '<div class="spec-card">'
      + '<h4>规格 ' + n + ' ' + removeSpec + '</h4>'
      + '<div class="field"><label>属性（名称 + 值）</label>' + attrRows
      + '<div class="toolbar"><button type="button" class="secondary" data-add-attr="' + n + '">添加属性</button></div>'
      + '<div class="field-error" data-err="spec:' + n + ':attributes"></div></div>'
      + '<div class="field"><label for="price-' + n + '">售价（十进制金额，最多两位小数，不为负数）</label>'
      + '<input type="text" id="price-' + n + '" inputmode="decimal" autocomplete="off" data-spec="' + n + '" data-field="price" value="' + esc(s.price) + '">'
      + '<div class="field-error" data-err="spec:' + n + ':price"></div></div>'
      + '<div class="field"><label for="stock-' + n + '">库存（非负整数）</label>'
      + '<input type="text" id="stock-' + n + '" inputmode="numeric" autocomplete="off" data-spec="' + n + '" data-field="stock" value="' + esc(s.stock) + '">'
      + '<div class="field-error" data-err="spec:' + n + ':stock"></div></div>'
      + '<div class="field-error" data-err="spec:' + n + ':duplicate"></div>'
      + '</div>';
  }).join('');
  container.querySelectorAll('input[data-field]').forEach(function(el){
    el.addEventListener('input', function(){
      var n = parseInt(el.getAttribute('data-spec'), 10) - 1;
      formState.specs[n][el.getAttribute('data-field')] = el.value;
    });
  });
  container.querySelectorAll('input[data-sub]').forEach(function(el){
    el.addEventListener('input', function(){
      var n = parseInt(el.getAttribute('data-spec'), 10) - 1;
      var an = parseInt(el.getAttribute('data-attr'), 10) - 1;
      formState.specs[n].attributes[an][el.getAttribute('data-sub')] = el.value;
    });
  });
  container.querySelectorAll('[data-add-attr]').forEach(function(el){
    el.addEventListener('click', function(){
      var n = parseInt(el.getAttribute('data-add-attr'), 10) - 1;
      formState.specs[n].attributes.push({name:'', value:''});
      renderSpecs();
      renderErrors();
    });
  });
  container.querySelectorAll('[data-remove-attr]').forEach(function(el){
    el.addEventListener('click', function(){
      var parts = el.getAttribute('data-remove-attr').split(':');
      var n = parseInt(parts[0], 10) - 1;
      var an = parseInt(parts[1], 10) - 1;
      formState.specs[n].attributes.splice(an, 1);
      renderSpecs();
      renderErrors();
    });
  });
  container.querySelectorAll('[data-remove-spec]').forEach(function(el){
    el.addEventListener('click', function(){
      var n = parseInt(el.getAttribute('data-remove-spec'), 10) - 1;
      formState.specs.splice(n, 1);
      renderSpecs();
      renderErrors();
    });
  });
}

function specErrorKey(e){
  if(e.scope === 'product') return 'product:' + e.field;
  if(e.field === 'duplicate') return 'spec:' + e.spec + ':duplicate';
  if(e.field === 'attribute' || (e.field === 'attributes' && e.attribute)){
    return 'spec:' + e.spec + ':attr:' + e.attribute + ':' + (e.subfield || '');
  }
  return 'spec:' + e.spec + ':' + e.field;
}

function renderErrors(){
  var map = {};
  formErrors.forEach(function(e){
    var k = specErrorKey(e);
    (map[k] = map[k] || []).push(e.message);
  });
  document.querySelectorAll('[data-err]').forEach(function(el){
    var key = el.getAttribute('data-err');
    var msgs = map[key];
    el.textContent = msgs ? msgs.join('；') : '';
  });
  document.querySelectorAll('input[data-field], input[data-sub], #fName').forEach(function(el){
    var key;
    if(el.id === 'fName'){
      key = 'product:name';
    } else if(el.hasAttribute('data-field')){
      key = 'spec:' + el.getAttribute('data-spec') + ':' + el.getAttribute('data-field');
    } else {
      key = 'spec:' + el.getAttribute('data-spec') + ':attr:' + el.getAttribute('data-attr') + ':' + el.getAttribute('data-sub');
    }
    var attrLevel = el.hasAttribute('data-sub')
      && !!map['spec:' + el.getAttribute('data-spec') + ':attributes'];
    el.classList.toggle('invalid', !!map[key] || attrLevel);
  });
  var notice = document.getElementById('formNotice');
  if(notice){
    notice.innerHTML = formErrors.length
      ? '<div class="error-box">表单存在问题，请根据下方提示修正后重新提交。已填写的内容都会保留。</div>'
      : '';
  }
}

var PRICE_RE = /^(0|[1-9]\d*)(\.\d{1,2})?$/;

function validateForm(){
  var errs = [];
  if(!formState.name.trim()){
    errs.push({scope:'product', field:'name', message:'商品名称不能为空'});
  }
  if(!formState.specs.length){
    errs.push({scope:'product', field:'specs', message:'商品至少需要一条规格'});
  }
  var specKeys = [];
  formState.specs.forEach(function(s, i){
    var n = i + 1;
    var attrs = s.attributes.map(function(a){ return {name:a.name.trim(), value:a.value.trim()}; });
    if(!attrs.length){
      errs.push({scope:'spec', spec:n, field:'attributes', message:'第' + n + '条规格至少需要一个属性'});
    }
    var names = {};
    attrs.forEach(function(a, j){
      var an = j + 1;
      if(!a.name){
        errs.push({scope:'spec', spec:n, field:'attribute', attribute:an, subfield:'name',
          message:'第' + n + '条规格第' + an + '个属性的名称不能为空'});
      }
      if(!a.value){
        errs.push({scope:'spec', spec:n, field:'attribute', attribute:an, subfield:'value',
          message:'第' + n + '条规格第' + an + '个属性的值不能为空'});
      }
      if(a.name){
        if(names[a.name]){
          errs.push({scope:'spec', spec:n, field:'attributes',
            message:'第' + n + '条规格内属性名称「' + a.name + '」重复'});
        } else {
          names[a.name] = true;
        }
      }
    });
    if(!PRICE_RE.test(s.price.trim())){
      errs.push({scope:'spec', spec:n, field:'price',
        message:'第' + n + '条规格售价格式不正确：须为十进制金额字符串，允许零和最多两位小数，不接受负数、指数写法或千位分隔符，也不会自动四舍五入'});
    }
    var stockRaw = s.stock.trim();
    var stockNum = stockRaw === '' ? NaN : Number(stockRaw);
    if(!Number.isSafeInteger(stockNum) || stockNum < 0){
      errs.push({scope:'spec', spec:n, field:'stock',
        message:'第' + n + '条规格库存必须为非负整数，不能把小数或空值当作零'});
    }
    if(attrs.length && attrs.every(function(a){ return a.name && a.value; })){
      var key = attrs.map(function(a){ return a.name + '=' + a.value; }).sort().join('&');
      if(specKeys.indexOf(key) !== -1){
        errs.push({scope:'spec', spec:n, field:'duplicate',
          message:'第' + n + '条规格与前面的规格重复：属性名称和值完全相同，与填写顺序无关，字母大小写区分'});
      } else {
        specKeys.push(key);
      }
    }
  });
  return errs;
}

function showNotice(kind, msg){
  var notice = document.getElementById('formNotice');
  if(notice){
    notice.innerHTML = '<div class="' + (kind === 'error' ? 'error-box' : 'success-box') + '">' + esc(msg) + '</div>';
  }
}

function submitForm(ev){
  ev.preventDefault();
  formErrors = validateForm();
  renderErrors();
  if(formErrors.length) return;
  var payload = {
    name: formState.name.trim(),
    specs: formState.specs.map(function(s){
      return {
        attributes: s.attributes.map(function(a){ return {name:a.name.trim(), value:a.value.trim()}; }),
        price: s.price.trim(),
        stock: Number(s.stock.trim())
      };
    })
  };
  fetch('/api/products', {
    method:'POST',
    headers:{'content-type':'application/json'},
    body: JSON.stringify(payload)
  }).then(function(res){
    return res.json().catch(function(){ return {}; }).then(function(data){
      return {status:res.status, data:data};
    });
  }).then(function(r){
    if(r.status === 201){
      formState = null;
      formErrors = [];
      justSaved = true;
      return loadProducts();
    }
    if(r.status === 400){
      formErrors = (r.data && Array.isArray(r.data.errors)) ? r.data.errors
        : [{scope:'product', field:'body', message:(r.data && r.data.error) || '提交内容不正确'}];
      renderErrors();
      showNotice('error', '商品未保存：提交内容存在问题，请根据下方提示修正后重新提交。已填写的内容都会保留。');
      return;
    }
    showNotice('error', '商品未保存：服务保存失败，请稍后重试。已有商品未受影响。');
  }).catch(function(){
    showNotice('error', '商品未保存：网络错误，请稍后重试。');
  });
}

loadProducts();
</script>
</html>`;

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
try { writeFileSync(dataFile, '[]\n', { flag: 'wx' }); } catch (error) {
  if (!(error instanceof Error && 'code' in error && error.code === 'EEXIST')) throw error;
}

const PRICE_RE: RegExp = /^(0|[1-9]\d*)(\.\d{1,2})?$/;

function normalizePrice(price: string): string {
  const dot = price.indexOf('.');
  if (dot === -1) return `${price}.00`;
  return `${price.slice(0, dot)}.${price.slice(dot + 1).padEnd(2, '0')}`;
}

function validateProduct(input: unknown): { errors: FieldError[]; value?: ProductRecord } {
  const errors: FieldError[] = [];
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    return { errors: [{ scope: 'product', field: 'body', message: '请求内容必须是商品对象' }] };
  }
  const obj = input as Record<string, unknown>;
  const name: string = typeof obj.name === 'string' ? obj.name.trim() : '';
  if (!name) errors.push({ scope: 'product', field: 'name', message: '商品名称不能为空' });

  if (!Array.isArray(obj.specs) || obj.specs.length === 0) {
    errors.push({ scope: 'product', field: 'specs', message: '商品至少需要一条规格' });
    return { errors };
  }

  const specs: SpecRecord[] = [];
  const seenSpecs = new Set<string>();
  obj.specs.forEach((rawSpec: unknown, i: number) => {
    const specNum: number = i + 1;
    if (typeof rawSpec !== 'object' || rawSpec === null || Array.isArray(rawSpec)) {
      errors.push({ scope: 'spec', spec: specNum, field: 'spec', message: `第${specNum}条规格的格式不正确` });
      return;
    }
    const spec = rawSpec as Record<string, unknown>;

    if (!Array.isArray(spec.attributes) || spec.attributes.length === 0) {
      errors.push({ scope: 'spec', spec: specNum, field: 'attributes', message: `第${specNum}条规格至少需要一个属性` });
    } else {
      const seenNames = new Set<string>();
      spec.attributes.forEach((rawAttr: unknown, j: number) => {
        const attrNum: number = j + 1;
        if (typeof rawAttr !== 'object' || rawAttr === null || Array.isArray(rawAttr)) {
          errors.push({ scope: 'spec', spec: specNum, field: 'attribute', attribute: attrNum,
            message: `第${specNum}条规格第${attrNum}个属性的格式不正确` });
          return;
        }
        const attr = rawAttr as Record<string, unknown>;
        const attrName: string = typeof attr.name === 'string' ? attr.name.trim() : '';
        const attrValue: string = typeof attr.value === 'string' ? attr.value.trim() : '';
        if (!attrName) {
          errors.push({ scope: 'spec', spec: specNum, field: 'attribute', attribute: attrNum, subfield: 'name',
            message: `第${specNum}条规格第${attrNum}个属性的名称不能为空` });
        }
        if (!attrValue) {
          errors.push({ scope: 'spec', spec: specNum, field: 'attribute', attribute: attrNum, subfield: 'value',
            message: `第${specNum}条规格第${attrNum}个属性的值不能为空` });
        }
        if (attrName) {
          if (seenNames.has(attrName)) {
            errors.push({ scope: 'spec', spec: specNum, field: 'attributes',
              message: `第${specNum}条规格内属性名称「${attrName}」重复` });
          } else {
            seenNames.add(attrName);
          }
        }
      });
    }

    let price: string | undefined;
    if (typeof spec.price !== 'string' || !PRICE_RE.test(spec.price)) {
      errors.push({ scope: 'spec', spec: specNum, field: 'price',
        message: `第${specNum}条规格的售价必须为十进制金额字符串：允许零和最多两位小数，不接受负数、指数写法、千位分隔符或超过两位的小数，也不会四舍五入` });
    } else {
      price = normalizePrice(spec.price);
    }

    let stock: number | undefined;
    if (typeof spec.stock !== 'number' || !Number.isSafeInteger(spec.stock) || spec.stock < 0) {
      errors.push({ scope: 'spec', spec: specNum, field: 'stock',
        message: `第${specNum}条规格的库存必须为非负安全整数，不能把小数或空值当作零` });
    } else {
      stock = spec.stock;
    }

    if (Array.isArray(spec.attributes) && spec.attributes.length > 0
      && spec.attributes.every((a: unknown) => typeof a === 'object' && a !== null && !Array.isArray(a)
        && typeof (a as Record<string, unknown>).name === 'string'
        && typeof (a as Record<string, unknown>).value === 'string'
        && ((a as Record<string, unknown>).name as string).trim()
        && ((a as Record<string, unknown>).value as string).trim())) {
      const key = spec.attributes
        .map((a: unknown) => {
          const at = a as Record<string, unknown>;
          return `${(at.name as string).trim()}=${(at.value as string).trim()}`;
        })
        .sort()
        .join('&');
      if (seenSpecs.has(key)) {
        errors.push({ scope: 'spec', spec: specNum, field: 'duplicate',
          message: `第${specNum}条规格与前面的规格重复：属性名称和值完全相同，与填写顺序无关，字母大小写区分` });
      } else {
        seenSpecs.add(key);
      }
    }

    if (price !== undefined && stock !== undefined
      && Array.isArray(spec.attributes) && spec.attributes.length > 0
      && spec.attributes.every((a: unknown) => typeof a === 'object' && a !== null && !Array.isArray(a)
        && typeof (a as Record<string, unknown>).name === 'string'
        && typeof (a as Record<string, unknown>).value === 'string'
        && ((a as Record<string, unknown>).name as string).trim()
        && ((a as Record<string, unknown>).value as string).trim())) {
      const attributes: AttributeRecord[] = spec.attributes.map((a: unknown) => {
        const at = a as Record<string, unknown>;
        return { name: (at.name as string).trim(), value: (at.value as string).trim() };
      });
      specs.push({ attributes, price, stock });
    }
  });

  if (errors.length) return { errors };
  return { errors: [], value: { id: randomUUID(), name, specs } };
}

function loadRecords(): ProductRecord[] {
  const records: unknown = JSON.parse(readFileSync(dataFile, 'utf8'));
  if (!Array.isArray(records)) throw new Error('Invalid record list');
  return records as ProductRecord[];
}

function saveRecords(records: ProductRecord[]): void {
  const tmpFile = join(dataDir, 'products.json.tmp');
  writeFileSync(tmpFile, JSON.stringify(records, null, 2) + '\n');
  renameSync(tmpFile, dataFile);
}

function respond(res: ServerResponse, status: number, value: unknown, html = false, allow?: string): void {
  const body = html ? String(value) : JSON.stringify(value);
  res.writeHead(status, {
    'content-type': html ? 'text/html; charset=utf-8' : 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    ...(allow ? { allow } : {})
  });
  res.end(body);
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > 1_000_000) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

const server = createServer(async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
  try {
    await handle(req, res);
  } catch (error) {
    console.error(error);
    if (!res.headersSent) respond(res, 500, { error: 'internal server error' });
  }
});

async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
  let route: string;
  try { route = new URL(req.url ?? '/', 'http://localhost').pathname; } catch { respond(res, 400, { error: 'invalid request path' }); return; }
  if (!['/', '/health', '/api/products'].includes(route)) { respond(res, 404, { error: 'not found' }); return; }
  if (route === '/') {
    if (req.method !== 'GET') { respond(res, 405, { error: 'method not allowed' }, false, 'GET'); return; }
    respond(res, 200, PAGE, true);
    return;
  }
  if (route === '/health') {
    if (req.method !== 'GET') { respond(res, 405, { error: 'method not allowed' }, false, 'GET'); return; }
    respond(res, 200, { status: 'ok', product: PRODUCT });
    return;
  }
  if (req.method === 'GET') {
    try {
      const records: ProductRecord[] = loadRecords();
      respond(res, 200, { [RESOURCE]: records });
    } catch {
      respond(res, 500, { error: 'unable to read products' });
    }
    return;
  }
  if (req.method === 'POST') {
    let raw: string;
    try { raw = await readBody(req); } catch { respond(res, 400, { error: 'unable to read request body' }); return; }
    let parsed: unknown;
    try { parsed = JSON.parse(raw); } catch { respond(res, 400, { error: '请求内容不是合法的JSON' }); return; }
    const { errors, value } = validateProduct(parsed);
    if (errors.length) { respond(res, 400, { error: '商品信息校验失败，未保存任何内容', errors }); return; }
    try {
      const records: ProductRecord[] = loadRecords();
      records.push(value as ProductRecord);
      saveRecords(records);
    } catch {
      respond(res, 500, { error: '商品保存失败，未保存任何内容，请重试' });
      return;
    }
    respond(res, 201, { product: value });
    return;
  }
  respond(res, 405, { error: 'method not allowed' }, false, 'GET, POST');
}

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
