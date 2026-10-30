// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const Q = require('..');
const key = () => Q.generateKey();
const reg = (k, o) => Q.register({ key: k, parcel: 'Parcel 12 / Block 7', tenure: 'freehold', areaM2: 540, jurisdiction: 'gb', owner: Q.keyId(o), registrarLabel: 'Land Registry' });

test('a registered title is a well formed signed record of the registrar', () => {
  const r = key(); const o = key(); const t = reg(r, o);
  assert.strictEqual(t.format, 'qestate/1');
  assert.strictEqual(t.type, 'register');
  assert.strictEqual(t.signer.id, Q.keyId(r));
  assert.strictEqual(t.statement.ownerKeyId, Q.keyId(o));
  assert.strictEqual(t.statement.tenure, 'freehold');
  assert.match(t.statement.titleId, /^[0-9a-f]{32}$/);
});

test('transfer charge discharge chain to the same title', () => {
  const r = key(); const o = key(); const buyer = key(); const bank = key();
  const t = reg(r, o);
  const moved = Q.transfer({ key: o, title: t, to: Q.keyId(buyer) });
  const ch = Q.charge({ key: r, title: t, creditor: Q.keyId(bank), creditorLabel: 'Bank' });
  const dis = Q.discharge({ key: r, title: t, chargeId: ch.statement.chargeId });
  assert.strictEqual(moved.statement.titleId, t.statement.titleId);
  assert.strictEqual(moved.statement.fromKeyId, Q.keyId(o));
  assert.strictEqual(ch.statement.creditorKeyId, Q.keyId(bank));
  assert.match(ch.statement.chargeId, /^[0-9a-f]{32}$/);
  assert.strictEqual(dis.statement.chargeId, ch.statement.chargeId);
});

test('invalid inputs are refused before anything is signed', () => {
  const k = key(); const o = key();
  const base = { key: k, parcel: 'P1', tenure: 'freehold', areaM2: 100, jurisdiction: 'gb', owner: Q.keyId(o) };
  assert.throws(() => Q.register(Object.assign({}, base, { tenure: 'rented' })), /tenure must be one of/);
  assert.throws(() => Q.register(Object.assign({}, base, { areaM2: 0 })), /areaM2 must be a whole number/);
  assert.throws(() => Q.register(Object.assign({}, base, { jurisdiction: 'GB' })), /jurisdiction must be/);
  assert.throws(() => Q.register(Object.assign({}, base, { zzz: 1 })), /is not an option of register/);
});

test('a well formed record verifies and a type mismatch or tamper is invalid', async () => {
  const r = key(); const o = key(); const t = reg(r, o);
  const OPTS = { network: 'testnet', requireAnchor: false, strict: false };
  const ok = await Q.verify(t, Object.assign({ type: 'register' }, OPTS));
  assert.strictEqual(ok.status, 'valid');
  assert.strictEqual(ok.titleId, t.statement.titleId);
  assert.strictEqual((await Q.verify(t, Object.assign({ type: 'transfer' }, OPTS))).status, 'invalid');
  const f = JSON.parse(JSON.stringify(t)); f.statement.areaM2 = 999;
  assert.strictEqual((await Q.verify(f, Object.assign({ type: 'register' }, OPTS))).status, 'invalid');
});

test('the prior link binds and the kind and constants are pinned', async () => {
  const r = key(); const o = key();
  const t = reg(r, o);
  const moved = Q.transfer({ key: o, title: t, to: Q.keyId(key()) });
  const good = await Q.verify(moved, { type: 'transfer', network: 'testnet', requireAnchor: false, strict: false, prior: t });
  assert.ok(good.checks.some((c) => c.name === 'prior' && c.ok));
  assert.strictEqual(Q.KIND, 1306);
  assert.strictEqual(Q.FORMAT, 'qestate/1');
  assert.deepStrictEqual([...Q.TYPES], ['register', 'transfer', 'charge', 'discharge']);
});
