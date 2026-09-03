import { test } from 'bun:test';
import assert from 'node:assert/strict';
import { createLoginStateStore } from '../../src/auth/login-state.mjs';

test('a real entry is readable exactly once', () => {
  const store = createLoginStateStore();
  assert.equal(store.hasPending('acct'), false);
  store.setReal('acct', Buffer.from('state'));
  assert.equal(store.hasPending('acct'), true);
  const entry = store.take('acct');
  assert.equal(entry.kind, 'real');
  assert.ok(Buffer.from(entry.stateBytes).equals(Buffer.from('state')));
  assert.equal(store.hasPending('acct'), false);
  assert.equal(store.take('acct'), null);
});

test('a fake entry behaves the same shape as a real one but carries no state', () => {
  const store = createLoginStateStore();
  store.setFake('unknown-acct');
  assert.equal(store.hasPending('unknown-acct'), true);
  const entry = store.take('unknown-acct');
  assert.equal(entry.kind, 'fake');
  assert.equal(store.hasPending('unknown-acct'), false);
});

test('entries expire after their TTL', async () => {
  const store = createLoginStateStore(20);
  store.setReal('acct', Buffer.from('state'));
  assert.equal(store.hasPending('acct'), true);
  await new Promise((resolve) => setTimeout(resolve, 40));
  assert.equal(store.hasPending('acct'), false);
  assert.equal(store.take('acct'), null);
});

test('accounts are independent', () => {
  const store = createLoginStateStore();
  store.setReal('a', Buffer.from('1'));
  store.setFake('b');
  assert.equal(store.hasPending('a'), true);
  assert.equal(store.hasPending('b'), true);
  assert.equal(store.take('a').kind, 'real');
  assert.equal(store.hasPending('b'), true);
  assert.equal(store.take('b').kind, 'fake');
});
