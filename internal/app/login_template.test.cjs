const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const vm = require('node:vm');

// Execute the page's actual controller with SDK/DOM doubles. Go tests cover
// rendering and escaping of the options preceding this controller.
const template = readFileSync(join(__dirname, 'login_template.go'), 'utf8');
const start = template.indexOf('    const button =');
const end = template.indexOf('  </script>', start);
assert.ok(start >= 0 && end > start);
const controller = template.slice(start, end);

function page() {
  const callbacks = {};
  const timers = new Map();
  const forms = [];
  const button = { disabled: false, setAttribute(name, value) { this[name] = value; } };
  const status = {};
  let submissions = 0;
  let authCalls = 0;
  let onAuth;
  const script = { addEventListener(name, cb) { callbacks['script-' + name] = cb; } };
  const sdk = {
    init(options, cb) { callbacks.init = cb; },
    auth(options, cb) { authCalls++; callbacks.auth = cb; if (onAuth) onAuth(cb); },
  };
  const window = {
    Telegram: { Login: sdk },
    setTimeout(cb) { const id = timers.size + 1; timers.set(id, cb); return id; },
    clearTimeout(id) { timers.delete(id); },
    addEventListener(name, cb) { callbacks[name] = cb; },
  };
  const document = {
    getElementById(id) { return id === 'login-button' ? button : id === 'status' ? status : script; },
    addEventListener(name, cb) { callbacks[name] = cb; },
    createElement(tag) { return { tag, children: [], appendChild(child) { this.children.push(child); }, submit() { submissions++; } }; },
    body: { appendChild(form) { forms.push(form); } },
  };
  vm.runInNewContext(controller, { window, document, Telegram: window.Telegram, loginOptions: {}, authAction: '/auth/telegram/123', state: 'fixture-state' });
  callbacks.load();
  return {
    callbacks, button, status, forms,
    get submissions() { return submissions; },
    get authCalls() { return authCalls; },
    set onAuth(cb) { onAuth = cb; },
    click() { callbacks.click(); },
    runTimers() { for (const cb of [...timers.values()]) cb(); },
  };
}

for (const order of [['init', 'auth'], ['auth', 'init']]) {
  test('one submission through both SDK callbacks: ' + order.join(', '), () => {
    const p = page();
    p.click();
    for (const name of order) p.callbacks[name]({ id_token: 'synthetic-token' });
    assert.equal(p.forms.length, 1);
    assert.equal(p.submissions, 1);
    assert.equal(p.button.disabled, true);
    assert.equal(p.button['aria-busy'], 'true');
    assert.equal(p.status.textContent, 'Completing sign-in...');
    assert.deepEqual(Object.fromEntries(p.forms[0].children.map(i => [i.name, i.value])), {
      id_token: 'synthetic-token', state: 'fixture-state', navigation: 'document',
    });
    p.callbacks.init(null);
    p.callbacks.auth({ error: 'late failure' });
    p.callbacks['script-error']();
    p.runTimers();
    p.click();
    assert.equal(p.submissions, 1);
    assert.equal(p.authCalls, 1);
    assert.equal(p.button.disabled, true);
    assert.equal(p.status.textContent, 'Completing sign-in...');
  });
}

test('slow phone confirmation does not permit another login', () => {
  const p = page();
  p.click();
  p.runTimers();
  p.click();
  assert.equal(p.authCalls, 1);
  assert.equal(p.button.disabled, true);
  p.callbacks.auth({ id_token: 'synthetic-token' });
  assert.equal(p.submissions, 1);
  assert.equal(p.button.disabled, true);
});

for (const result of [null, { error: 'cancelled' }, {}]) {
  test('failure before submission permits retry: ' + JSON.stringify(result), () => {
    const p = page();
    p.click();
    p.callbacks.auth(result);
    assert.equal(p.forms.length, 0);
    assert.equal(p.button.disabled, false);
    p.click();
    assert.equal(p.authCalls, 2);
    p.callbacks.auth({ id_token: 'synthetic-token' });
    assert.equal(p.submissions, 1);
  });
}

test('SDK exceptions recover only before successful submission', () => {
  const p = page();
  p.onAuth = () => { throw new Error('popup failed'); };
  p.click();
  assert.equal(p.button.disabled, false);
  p.onAuth = cb => { cb({ id_token: 'synthetic-token' }); throw new Error('late exception'); };
  p.click();
  assert.equal(p.submissions, 1);
  assert.equal(p.button.disabled, true);
  assert.equal(p.status.textContent, 'Completing sign-in...');
});

test('an init callback can submit before the first click', () => {
  const p = page();
  p.callbacks.init({ id_token: 'synthetic-token' });
  p.click();
  assert.equal(p.submissions, 1);
  assert.equal(p.authCalls, 0);
  assert.equal(p.button.disabled, true);
});
