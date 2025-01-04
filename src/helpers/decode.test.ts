/**
 * @license
The MIT License (MIT)

Copyright (c) 2015 Auth0, Inc. <support@auth0.com> (http://auth0.com)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 */

/**
 * Pulled this file out of jwt-decode to use in this project.
 * It's fairly straightforward and pulling it in means no dependency outside.
 * Especially for code that hasn't changed in years.
 */

import { describe, it } from "node:test";
import assert from "node:assert";
import {jwtDecode, type JwtPayload, InvalidTokenError} from './decode.ts';

const token =
  "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJleHAiOjEzOTMyODY4OTMsImlhdCI6MTM5MzI2ODg5M30.4-iaDojEVl0pJQMjrbM1EzUIfAZgsbK_kgnVyVxFSVo";

describe("jwt-decode", () => {
  it("should return default and custom claims", () => {
    const decoded = jwtDecode<JwtPayload & { foo: string }>(token);

    assert.strictEqual(decoded.exp, 1393286893);
    assert.strictEqual(decoded.iat, 1393268893);
    assert.strictEqual(decoded.foo, "bar");
  });

  it("should return header information", () => {
    const decoded = jwtDecode(token, { header: true });

    assert.strictEqual(decoded.alg, "HS256");
    assert.strictEqual(decoded.typ, "JWT");
  });

  it("should work with utf8 tokens", () => {
    const utf8Token =
      "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiSm9zw6kiLCJpYXQiOjE0MjU2NDQ5NjZ9.1CfFtdGUPs6q8kT3OGQSVlhEMdbuX0HfNSqum0023a0";
    const decoded = jwtDecode<JwtPayload & { name: string }>(utf8Token);

    assert.strictEqual(decoded.name, "José");
  });

  it("should work with binary tokens", () => {
    const binaryToken =
      "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiSm9z6SIsImlhdCI6MTQyNTY0NDk2Nn0.cpnplCBxiw7Xqz5thkqs4Mo_dymvztnI0CI4BN0d1t8";
    const decoded = jwtDecode<JwtPayload & { name: string }>(binaryToken);

    assert.strictEqual(decoded.name, "José");
  });

  it("should work with double padding", () => {
    const utf8Token =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikpvc8OpIiwiaWF0IjoxNTE2MjM5MDIyfQ.7A3F5SUH2gbBSYVon5mas_Y-KCrWojorKQg7UKGVEIA";
    const decoded = jwtDecode<JwtPayload & { name: string }>(utf8Token);

    assert.strictEqual(decoded.name, "José");
  });

  it("should work with single padding", () => {
    const utf8Token =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ikpvc8OpZSIsImlhdCI6MTUxNjIzOTAyMn0.tbjJzDAylkKSV0_YGR5xBJBlFK01C82nZPLIcA3JX1g";
    const decoded = jwtDecode<JwtPayload & { name: string }>(utf8Token);

    assert.strictEqual(decoded.name, "Josée");
  });

  it("should throw InvalidTokenError on nonstring", () => {
    const badToken = null;

    assert.throws(() => {
      jwtDecode(badToken as unknown as string);
    }, InvalidTokenError);
  });

  it("should throw InvalidTokenError on string that is not a token", () => {
    const badToken = "fubar";

    assert.throws(() => {
      jwtDecode(badToken);
    }, InvalidTokenError);
  });

  it("should throw InvalidTokenErrors when token is null", () => {
    const badToken = null;

    assert.throws(() => {
      jwtDecode(badToken as unknown as string, { header: true });
    }, new InvalidTokenError("Invalid token specified: must be a string"));
  });

  it("should throw InvalidTokenErrors when missing part #1", () => {
    const badToken = ".FAKE_TOKEN";

    assert.throws(() => {
      jwtDecode(badToken, { header: true });
    }, /Invalid token specified: invalid json for part #1/);
  });

  it("should throw InvalidTokenErrors when part #1 is not valid base64", () => {
    const badToken = "TOKEN";

    assert.throws(() => {
      jwtDecode(badToken, { header: true });
    }, /Invalid token specified: invalid base64 for part #1/);
  });

  it("should throw InvalidTokenErrors when part #1 is not valid JSON", () => {
    const badToken = "FAKE.TOKEN";

    assert.throws(() => {
      jwtDecode(badToken, { header: true });
    }, /Invalid token specified: invalid json for part #1/);
  });

  it("should throw InvalidTokenErrors when missing part #2", () => {
    const badToken = "FAKE_TOKEN";

    assert.throws(() => {
      jwtDecode(badToken);
    }, new InvalidTokenError("Invalid token specified: missing part #2"));
  });

  it("should throw InvalidTokenErrors when part #2 is not valid base64", () => {
    const badToken = "FAKE.TOKEN";

    assert.throws(() => {
      jwtDecode(badToken);
    }, /Invalid token specified: invalid base64 for part #2/);
  });

  it("should throw InvalidTokenErrors when part #2 is not valid JSON", () => {
    const badToken = "FAKE.TOKEN2";

    assert.throws(() => {
      jwtDecode(badToken);
    }, /Invalid token specified: invalid json for part #2/);
  });
});
