import test from 'node:test';
import assert from 'node:assert/strict';
import { getNextThemeMode, getThemeLabel, normalizeThemeMode, resolveIsDark } from './theme';

test('normalizeThemeMode defaults invalid or missing values to system', () => {
  assert.equal(normalizeThemeMode(null), 'system');
  assert.equal(normalizeThemeMode(undefined), 'system');
  assert.equal(normalizeThemeMode('midnight'), 'system');
  assert.equal(normalizeThemeMode('dark'), 'dark');
  assert.equal(normalizeThemeMode('light'), 'light');
  assert.equal(normalizeThemeMode('system'), 'system');
});

test('resolveIsDark respects explicit mode and falls back to system preference', () => {
  assert.equal(resolveIsDark('dark', false), true);
  assert.equal(resolveIsDark('light', true), false);
  assert.equal(resolveIsDark('system', true), true);
  assert.equal(resolveIsDark('system', false), false);
});

test('getNextThemeMode cycles system -> dark -> light -> system', () => {
  assert.equal(getNextThemeMode('system'), 'dark');
  assert.equal(getNextThemeMode('dark'), 'light');
  assert.equal(getNextThemeMode('light'), 'system');
});

test('getThemeLabel returns concise accessible labels', () => {
  assert.equal(getThemeLabel('system'), 'Auto');
  assert.equal(getThemeLabel('dark'), 'Dark');
  assert.equal(getThemeLabel('light'), 'Light');
});
