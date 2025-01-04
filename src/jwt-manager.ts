import { jwtDecode, type JwtPayload } from 'jwt-decode';
import { CriteriaNotBeforeError } from './errors/criteria-not-before.ts';
import { TokenExpired } from './errors/token-expired.ts';

class JwtManager<PayloadOverload extends JwtPayload> {
  /**
   * The local storage system to use for keeping the token.
   * Defaults to session storage so it expires by default
   * with the session for the simplest security system.
   */
  #storageType: 'session' | 'local' = 'session';

  /**
   * The name of the key used when storing the token in
   * storage.
   */
  #key: string;

  /**
   * Retrieve the configured storage system to use.
   */
  get storageType() {
    return this.#storageType;
  }

  /**
   * Get the storage system from the browser.
   */
  get storage(): Storage {
    if (this.#storageType === 'local') {
      return window.localStorage;
    }

    return window.sessionStorage;
  }

  /**
   * Provide the token value that should be stored.
   * This will validate it is not expired before storage.
   * If expired, the token will not be stored since it is
   * not usable. When the token is valid, it is stored in
   * the storage system configured at initialization.
   */
  set token(value: string) {
    this.#isValidTime(value);

    this.storage.setItem(this.#key, value);
  }

  /**
   * Retrieve the token string value from storage.
   * If the the token is expired upon retrieval, it is
   * removed from storage and undefined is returned as if
   * no token is set. Otherwise, the string value is
   * returned.
   */
  get token(): string | undefined {
    const token = this.storage.getItem(this.#key);

    if (token === null) {
      return undefined;
    }

    try {
      this.#isValidTime(token);
    } catch {
      this.storage.removeItem(this.#key);

      return undefined
    }

    return token;
  }

  /**
   * Retrieve the body of the JWT data as an object.
   * If the JWT is expired or not present, undefined is
   * returned.
   */
  get data(): PayloadOverload | undefined {
    const {token} = this;

    if (token === undefined) {
      return undefined;
    }

    return this.#decode(token);
  }

  /**
   * Retrieve the issuer of the JWT if it is present.
   */
  get issuer(): string | undefined {
    return this.data?.iss;
  }

  /**
   * Retrieve the expiration time of the JWT if it is present.
   */
  get expirationTime(): number | undefined {
    return this.data?.exp;
  }

  get subject(): string | undefined {
    return this.data?.sub;
  }

  get audience(): string | string[] | undefined {
    return this.data?.aud;
  }

  get notBefore(): number | undefined {
    return this.data?.nbf;
  }

  get issuedAt(): number | undefined {
    return this.data?.iat;
  }

  get jwtId(): string | undefined {
    return this.data?.jti;
  }

  constructor(
    key: string,
    storageType: 'session' | 'local' = 'session',
  ) {
    this.#key = key;
    this.#storageType = storageType;
  }

  /**
   * Decode the token into an object from the string value.
   */
  #decode(token: string): PayloadOverload {
    return jwtDecode<PayloadOverload>(token);
  }

  /**
   * Determine the validity based on the `exp` and `nbf`
   * fields. If the `nbf` field is present, verify the current
   * time is after it. If the `exp` field is not present,
   * the token is valid indefinitely. Otherwise, compare
   * `exp` against current time to ensure it has not passed.
   */
  #isValidTime(token: string): void {
    const decoded = this.#decode(token);
    const currentTime = Math.floor(Date.now() / 1000);

    if (
      decoded.nbf &&
      currentTime < decoded.nbf
    ) {
        throw new CriteriaNotBeforeError(decoded.nbf, currentTime);
    }

    if (!decoded.exp) {
      return undefined;
    }

    if(decoded.exp <= currentTime) {
      throw new TokenExpired(decoded.exp, currentTime);
    }
  }
}

export {
  JwtManager,
};
