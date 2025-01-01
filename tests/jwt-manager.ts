import { test, expect } from '@playwright/test';
import { JwtManager } from '../src/jwt-manager.js';
import { createMockJwt } from './fixtures/create-jwt.js';
import {resolve} from 'path';
import esbuild from 'esbuild';

declare global {
  interface Window {
    jwtManInstance: JwtManager<object>;
    JwtManager: typeof JwtManager;
  }
}

const tsFilePath = resolve(import.meta.dirname, 'fixtures', 'inject-manager.ts');

const jsCode = esbuild.buildSync({
  entryPoints: [tsFilePath],
  bundle: true,
  write: false,
  format: 'iife',
  platform: 'browser',
}).outputFiles[0].text;

console.log(jsCode);

test.beforeEach(async ({page}) => {
  await page.goto('https://example.com');
  await page.evaluate(jsCode);
  await page.evaluate(() => {
    window.jwtManInstance = new window.JwtManager('auth_token');
  });
});

test('can store jwt', async ({page}) => {
  const jwtPayload = {
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() + 10000),
    name: 'Test',
    sub: '123',
  };

  const mockJwt = createMockJwt(jwtPayload);

  const result = await page.evaluate((token) => {
    window.jwtManInstance.token = token;

    return window.sessionStorage.getItem('auth_token');
  }, mockJwt);

  expect(result).toEqual(mockJwt);
});

test('checks expiration time', async ({page}) => {
  await page.clock.install({ time: new Date() });

  const jwtPayload = {
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() + 1000),
    name: 'Test',
    sub: '123',
  };

  const mockJwt = createMockJwt(jwtPayload);

  await page.evaluate((token) => {
    window.jwtManInstance.token = token;
  }, mockJwt);

  await page.clock.setFixedTime(Math.floor(Date.now() + 2000));


  const result = await page.evaluate(() => {
    return window.jwtManInstance.token;
  });

  expect(result).toBeUndefined();
});
