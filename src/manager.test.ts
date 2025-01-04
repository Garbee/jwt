import { afterEach, beforeEach, describe, it, mock } from 'node:test';
import assert from 'node:assert';
import {JwtManager} from '@garbee/jwt/manager.js';
import {createMockJwt} from '@garbee/jwt/create-mock.js';

declare global {
  namespace NodeJS {
    interface Global {
      window: Window;
    }
  }
}

const makeMockStorage = () =>  { return {
  storage: {} as Record<string, string>,
  get length(): number {
    return Object.keys(this.storage).length;
  },
  key(index: number): string | null {
    const keys = Object.keys(this.storage);
    return keys[index] || null;
  },
  getItem(key: string): string | null {
    return this.storage[key] || null;
  },
  setItem(key: string, value: string): void {
    this.storage[key] = value;
  },
  removeItem(key: string): void {
    delete this.storage[key];
  },
  clear(): void {
    this.storage = {};
  },
}};

describe('JwtManager', () => {
  let jwtManInstance: JwtManager<object>;

  beforeEach(() => {
    // @ts-expect-error
    global.window = {};
    global.window.sessionStorage = makeMockStorage();
    global.window.localStorage = makeMockStorage();

    mock.timers.enable({
      apis: ['setInterval', 'setTimeout', 'setImmediate', 'Date'],
      now: new Date(),
    });

    jwtManInstance = new JwtManager('auth_token');
  });

  afterEach(() => {
    // @ts-expect-error
    delete global.window;

    mock.timers.reset();
  });


  it('can store jwt',  () => {
    const jwtPayload = {
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor((Date.now() + 2000) / 1000),
      name: 'can store jwt Test',
      sub: '123',
    };

    const mockJwt = createMockJwt(jwtPayload);

    jwtManInstance.token = mockJwt;

    assert.strictEqual(window.sessionStorage.getItem('auth_token'), mockJwt);
    assert.strictEqual(jwtManInstance.token, mockJwt);
  });

  describe('isValidTime', () => {
    it('checks not before time', () => {
      const jwtPayload = {
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor((Date.now() + 5000) / 1000),
        name: 'checks not before time Test',
        sub: '123',
        nbf: Math.floor((Date.now() + 2000) / 1000),
      };

      const mockJwt = createMockJwt(jwtPayload);

      assert.throws(() => {
        jwtManInstance.token = mockJwt;
      });
      assert.strictEqual(jwtManInstance.token, undefined);
    });

    it('checks expiration time', () => {
      const jwtPayload = {
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor((Date.now() + 1000) / 1000),
        name: 'checks expiration time Test',
        sub: '123',
      };

      const mockJwt = createMockJwt(jwtPayload);
      jwtManInstance.token = mockJwt;

      assert.strictEqual(jwtManInstance.token, mockJwt);

      mock.timers.tick(2000);

      assert.strictEqual(jwtManInstance.token, undefined);
    });
  });

  describe('retrieves properties when set', () => {
    it('expirationTime', () => {
      const jwtPayload = {
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor((Date.now() + 3000) / 1000),
        name: 'expiration time set Test',
      };

      const mockJwt = createMockJwt(jwtPayload);
      jwtManInstance.token = mockJwt;

      assert.strictEqual(jwtManInstance.expirationTime, jwtPayload.exp);
    });

    it('issuer', () => {
      const jwtPayload = {
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor((Date.now() + 3000) / 1000),
        name: 'issuer set Test',
        iss: '123',
      };

      const mockJwt = createMockJwt(jwtPayload);
      jwtManInstance.token = mockJwt;

      assert.strictEqual(jwtManInstance.issuer, '123');
    });

    it('subject', () => {
      const jwtPayload = {
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor((Date.now() + 3000) / 1000),
        name: 'subject set Test',
        sub: '123',
      };

      const mockJwt = createMockJwt(jwtPayload);
      jwtManInstance.token = mockJwt;

      assert.strictEqual(jwtManInstance.subject, '123');
    });

    it('audience', () => {
      const jwtPayload = {
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor((Date.now() + 3000) / 1000),
        name: 'audience set Test',
        aud: '123',
      };

      const mockJwt = createMockJwt(jwtPayload);
      jwtManInstance.token = mockJwt;

      assert.strictEqual(jwtManInstance.audience, '123');
    });

    it('notBefore', () => {
      const jwtPayload = {
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor((Date.now() + 6000) / 1000),
        name: 'not before set Test',
        nbf: Math.floor((Date.now() + 2000) / 1000),
      };

      const mockJwt = createMockJwt(jwtPayload);

      mock.timers.tick(2000);

      jwtManInstance.token = mockJwt;

      assert.strictEqual(
        jwtManInstance.notBefore,
        jwtPayload.nbf,
      );
    });

    it('issuedAt', () => {
      const jwtPayload = {
        exp: Math.floor((Date.now() + 3000) / 1000),
        name: 'issued at set Test',
        iat: Math.floor(Date.now() / 1000),
      };

      const mockJwt = createMockJwt(jwtPayload);
      jwtManInstance.token = mockJwt;

      assert.strictEqual(jwtManInstance.issuedAt, Math.floor(Date.now() / 1000));
    });

    it('jwtId', () => {
      const jwtPayload = {
        exp: Math.floor((Date.now() + 3000) / 1000),
        name: 'jwt id set Test',
        jti: '123',
      };

      const mockJwt = createMockJwt(jwtPayload);
      jwtManInstance.token = mockJwt;

      assert.strictEqual(jwtManInstance.jwtId, '123');
    });
  });

  describe('retrieves undefined for properties when not set', () => {
    it('expirationTime', () => {
      const jwtPayload = {
        iat: Math.floor(Date.now() / 1000),
        name: 'expiration time not set Test',
      };

      const mockJwt = createMockJwt(jwtPayload);
      jwtManInstance.token = mockJwt;

      assert.strictEqual(jwtManInstance.expirationTime, undefined);
    });

    it('issuer', () => {
      const jwtPayload = {
        iat: Math.floor(Date.now() / 1000),
        name: 'issuer not set Test',
      };

      const mockJwt = createMockJwt(jwtPayload);
      jwtManInstance.token = mockJwt;

      assert.strictEqual(jwtManInstance.issuer, undefined);
    });

    it('subject', () => {
      const jwtPayload = {
        iat: Math.floor(Date.now() / 1000),
        name: 'subject not set Test',
      };

      const mockJwt = createMockJwt(jwtPayload);
      jwtManInstance.token = mockJwt;

      assert.strictEqual(jwtManInstance.subject, undefined);
    });

    it('audience', () => {
      const jwtPayload = {
        iat: Math.floor(Date.now() / 1000),
        name: 'audience not set Test',
      };

      const mockJwt = createMockJwt(jwtPayload);
      jwtManInstance.token = mockJwt;

      assert.strictEqual(jwtManInstance.audience, undefined);
    });

    it('notBefore', () => {
      const jwtPayload = {
        iat: Math.floor(Date.now() / 1000),
        name: 'not before not set Test',
      };

      const mockJwt = createMockJwt(jwtPayload);
      jwtManInstance.token = mockJwt;

      assert.strictEqual(jwtManInstance.notBefore, undefined);
    });

    it('issuedAt', () => {
      const jwtPayload = {
        name: 'issued at not set Test',
      };

      const mockJwt = createMockJwt(jwtPayload);
      jwtManInstance.token = mockJwt;

      assert.strictEqual(jwtManInstance.issuedAt, undefined);
    });

    it('jwtId', () => {
      const jwtPayload = {
        name: 'jwtId not set',
      };

      const mockJwt = createMockJwt(jwtPayload);
      jwtManInstance.token = mockJwt;

      assert.strictEqual(jwtManInstance.jwtId, undefined);
    });
  });

  describe('storage type is configurable', () => {

    it('can use localStorage', () => {
      const jwtManInstance = new JwtManager('auth_token', 'local');

      const jwtPayload = {
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor((Date.now() + 2000) / 1000),
        name: 'can store jwt Test',
        sub: '123',
      };

      const mockJwt = createMockJwt(jwtPayload);

      jwtManInstance.token = mockJwt;

      assert.strictEqual(window.localStorage.getItem('auth_token'), mockJwt);
      assert.strictEqual(jwtManInstance.token, mockJwt);
      assert.strictEqual(jwtManInstance.storageType, 'local');
    });

    it('can use sessionStorage', () => {
      const jwtManInstance = new JwtManager('auth_token', 'session');

      const jwtPayload = {
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor((Date.now() + 2000) / 1000),
        name: 'can store jwt Test',
        sub: '123',
      };

      const mockJwt = createMockJwt(jwtPayload);

      jwtManInstance.token = mockJwt;

      assert.strictEqual(window.sessionStorage.getItem('auth_token'), mockJwt);
      assert.strictEqual(jwtManInstance.token, mockJwt);
      assert.strictEqual(jwtManInstance.storageType, 'session');
    });
  });

  describe('data can be retrieved', () => {
    it('returns the data object', () => {
      const jwtPayload = {
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor((Date.now() + 2000) / 1000),
        name: 'can store jwt Test',
        sub: '123',
      };

      const mockJwt = createMockJwt(jwtPayload);

      jwtManInstance.token = mockJwt;

      assert.deepStrictEqual(jwtManInstance.data, jwtPayload);
    });
  });

  it('returns undefined when the token is invalid', () => {
    const jwtPayload = {
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor((Date.now() + 2000) / 1000),
      name: 'can store jwt Test',
      sub: '123',
    };

    const mockJwt = createMockJwt(jwtPayload);

    jwtManInstance.token = mockJwt;

    mock.timers.tick(2000);

    assert.strictEqual(jwtManInstance.data, undefined);
  });
});
